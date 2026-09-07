use std::ops::Range;

use crate::{core::EthSpec, beacon_state_summary::BeaconStateSummary};

/// The `List`/`ProgressiveList` fields of `BeaconStateSummary` that get split into
/// [`BeaconStatePart`](super::BeaconStatePart) chunks, in the same order they're declared on
/// `BeaconStateSummary` — `chunk_index` in `beacon_state_parts_by_range` is a single flat `u64`
/// with no field selector, so client and server must agree on one global numbering, and this
/// declaration order is the simplest scheme consistent with that request shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkedField {
    HistoricalRoots,
    Eth1DataVotes,
    Validators,
    Balances,
    PreviousEpochParticipation,
    CurrentEpochParticipation,
    InactivityScores,
    HistoricalSummaries,
    PendingDeposits,
    PendingPartialWithdrawals,
    PendingConsolidations,
    Builders,
    BuilderPendingWithdrawals,
    PayloadExpectedWithdrawals,
}

impl ChunkedField {
    /// All chunked fields, in `BeaconStateSummary`'s declaration order.
    pub const ALL: [ChunkedField; 14] = [
        ChunkedField::HistoricalRoots,
        ChunkedField::Eth1DataVotes,
        ChunkedField::Validators,
        ChunkedField::Balances,
        ChunkedField::PreviousEpochParticipation,
        ChunkedField::CurrentEpochParticipation,
        ChunkedField::InactivityScores,
        ChunkedField::HistoricalSummaries,
        ChunkedField::PendingDeposits,
        ChunkedField::PendingPartialWithdrawals,
        ChunkedField::PendingConsolidations,
        ChunkedField::Builders,
        ChunkedField::BuilderPendingWithdrawals,
        ChunkedField::PayloadExpectedWithdrawals,
    ];

    /// Max items per chunk for this field: the largest power of two `P` such that
    /// `P * ssz_fixed_len(item) <= 0.5 MiB`, targeting Etan's `<0.5MB` per-chunk constraint.
    ///
    /// Confirmed against Etan's three known values (`validators` = 2^12, `balances` = 2^16,
    /// `previous_epoch_participation` = 2^19) using each item type's real SSZ-encoded size from
    /// this crate — all three match this formula exactly. The rest of the table is derived the
    /// same way and hasn't been independently confirmed with Etan.
    pub const fn items_per_chunk(self) -> usize {
        match self {
            ChunkedField::HistoricalRoots => 1 << 14,           // Hash256, 32B
            ChunkedField::Eth1DataVotes => 1 << 12,             // Eth1Data, 72B
            ChunkedField::Validators => 1 << 12,                // Validator, 121B
            ChunkedField::Balances => 1 << 16,                  // u64, 8B
            ChunkedField::PreviousEpochParticipation => 1 << 19, // ParticipationFlags, 1B
            ChunkedField::CurrentEpochParticipation => 1 << 19,  // ParticipationFlags, 1B
            ChunkedField::InactivityScores => 1 << 16,          // u64, 8B
            ChunkedField::HistoricalSummaries => 1 << 13,       // HistoricalSummary, 64B
            ChunkedField::PendingDeposits => 1 << 11,           // PendingDeposit, 192B
            ChunkedField::PendingPartialWithdrawals => 1 << 14, // PendingPartialWithdrawal, 24B
            ChunkedField::PendingConsolidations => 1 << 15,     // PendingConsolidation, 16B
            ChunkedField::Builders => 1 << 12,                  // Builder, 93B
            ChunkedField::BuilderPendingWithdrawals => 1 << 13, // BuilderPendingWithdrawal, 36B
            ChunkedField::PayloadExpectedWithdrawals => 1 << 13, // Withdrawal, 44B
        }
    }

    /// Number of chunks a field with `len` items splits into (0 items → 0 chunks).
    pub fn num_chunks(self, len: usize) -> usize {
        len.div_ceil(self.items_per_chunk())
    }
}

/// Maps a flat, global `chunk_index` (as used by `beacon_state_parts_by_range`) to the specific
/// field and item-index range within that field the chunk covers, given the actual lengths of
/// every chunked field (from a [`BeaconStateSummary`]'s `ListSummary`s).
///
/// Chunks are laid out as a flat concatenation of each field's chunks, in [`ChunkedField::ALL`]
/// order: all of `historical_roots`'s chunks, then all of `eth1_data_votes`'s, and so on.
#[derive(Debug, Clone)]
pub struct ChunkLayout {
    /// `(field, num_chunks, first_global_index)` for each chunked field, in declaration order.
    per_field: Vec<(ChunkedField, usize, u64)>,
    total_chunks: u64,
}

impl ChunkLayout {
    /// Build a layout from each chunked field's length, in [`ChunkedField::ALL`] order.
    pub fn new(lengths: [usize; 14]) -> Self {
        let mut per_field = Vec::with_capacity(ChunkedField::ALL.len());
        let mut total_chunks: u64 = 0;
        for (field, len) in ChunkedField::ALL.into_iter().zip(lengths) {
            let num_chunks = field.num_chunks(len) as u64;
            per_field.push((field, field.num_chunks(len), total_chunks));
            total_chunks = total_chunks.saturating_add(num_chunks);
        }
        Self {
            per_field,
            total_chunks,
        }
    }

    /// Build a layout directly from a [`BeaconStateSummary`]'s `ListSummary` lengths.
    pub fn from_summary<E: EthSpec>(summary: &BeaconStateSummary<E>) -> Self {
        Self::new([
            summary.historical_roots.num_items as usize,
            summary.eth1_data_votes.num_items as usize,
            summary.validators.num_items as usize,
            summary.balances.num_items as usize,
            summary.previous_epoch_participation.num_items as usize,
            summary.current_epoch_participation.num_items as usize,
            summary.inactivity_scores.num_items as usize,
            summary.historical_summaries.num_items as usize,
            summary.pending_deposits.num_items as usize,
            summary.pending_partial_withdrawals.num_items as usize,
            summary.pending_consolidations.num_items as usize,
            summary.builders.num_items as usize,
            summary.builder_pending_withdrawals.num_items as usize,
            summary.payload_expected_withdrawals.num_items as usize,
        ])
    }

    /// Total number of chunks across every field, for validating a `(start_chunk, count)` request.
    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    /// Resolve a global `chunk_index` to the field it belongs to and the item-index range within
    /// that field this chunk covers. Returns `None` if `chunk_index >= total_chunks()`.
    pub fn locate(&self, chunk_index: u64) -> Option<(ChunkedField, Range<usize>)> {
        for &(field, num_chunks, first_global_index) in &self.per_field {
            let num_chunks = num_chunks as u64;
            if chunk_index < first_global_index.saturating_add(num_chunks) {
                let local_chunk_index = chunk_index.saturating_sub(first_global_index) as usize;
                let items_per_chunk = field.items_per_chunk();
                let start = local_chunk_index.saturating_mul(items_per_chunk);
                let end = start.saturating_add(items_per_chunk);
                return Some((field, start..end));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_per_chunk_matches_etan_known_values() {
        assert_eq!(ChunkedField::Validators.items_per_chunk(), 1 << 12);
        assert_eq!(ChunkedField::Balances.items_per_chunk(), 1 << 16);
        assert_eq!(
            ChunkedField::PreviousEpochParticipation.items_per_chunk(),
            1 << 19
        );
    }

    #[test]
    fn empty_field_has_zero_chunks() {
        assert_eq!(ChunkedField::Balances.num_chunks(0), 0);
    }

    #[test]
    fn num_chunks_rounds_up() {
        let per_chunk = ChunkedField::Validators.items_per_chunk();
        assert_eq!(ChunkedField::Validators.num_chunks(per_chunk), 1);
        assert_eq!(ChunkedField::Validators.num_chunks(per_chunk + 1), 2);
        assert_eq!(ChunkedField::Validators.num_chunks(per_chunk - 1), 1);
    }

    #[test]
    fn layout_locates_chunks_across_fields() {
        // historical_roots: 0 items -> 0 chunks.
        // eth1_data_votes: 1 item -> 1 chunk, global index 0.
        // validators: 2 * items_per_chunk items -> 2 chunks, global indices 1 and 2.
        // everything else: 0 items -> 0 chunks.
        let validators_per_chunk = ChunkedField::Validators.items_per_chunk();
        let lengths = [
            0,
            1,
            validators_per_chunk * 2,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let layout = ChunkLayout::new(lengths);
        assert_eq!(layout.total_chunks(), 3);

        let (field, range) = layout.locate(0).unwrap();
        assert_eq!(field, ChunkedField::Eth1DataVotes);
        assert_eq!(range, 0..ChunkedField::Eth1DataVotes.items_per_chunk());

        let (field, range) = layout.locate(1).unwrap();
        assert_eq!(field, ChunkedField::Validators);
        assert_eq!(range, 0..validators_per_chunk);

        let (field, range) = layout.locate(2).unwrap();
        assert_eq!(field, ChunkedField::Validators);
        assert_eq!(range, validators_per_chunk..(validators_per_chunk * 2));

        assert!(layout.locate(3).is_none());
    }
}
