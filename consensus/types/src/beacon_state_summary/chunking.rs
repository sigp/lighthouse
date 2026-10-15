use std::ops::Range;

use crate::{beacon_state_summary::BeaconStateSummary, core::EthSpec};

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
            ChunkedField::HistoricalRoots => 1 << 14, // Hash256, 32B
            ChunkedField::Eth1DataVotes => 1 << 12,   // Eth1Data, 72B
            ChunkedField::Validators => 1 << 12,      // Validator, 121B
            ChunkedField::Balances => 1 << 16,        // u64, 8B
            ChunkedField::PreviousEpochParticipation => 1 << 19, // ParticipationFlags, 1B
            ChunkedField::CurrentEpochParticipation => 1 << 19, // ParticipationFlags, 1B
            ChunkedField::InactivityScores => 1 << 16, // u64, 8B
            ChunkedField::HistoricalSummaries => 1 << 13, // HistoricalSummary, 64B
            ChunkedField::PendingDeposits => 1 << 11, // PendingDeposit, 192B
            ChunkedField::PendingPartialWithdrawals => 1 << 14, // PendingPartialWithdrawal, 24B
            ChunkedField::PendingConsolidations => 1 << 15, // PendingConsolidation, 16B
            ChunkedField::Builders => 1 << 12,        // Builder, 93B
            ChunkedField::BuilderPendingWithdrawals => 1 << 13, // BuilderPendingWithdrawal, 36B
            ChunkedField::PayloadExpectedWithdrawals => 1 << 13, // Withdrawal, 44B
        }
    }

    /// Number of items in this field's first chunk.
    ///
    /// A `ProgressiveList`'s tree is a chain of perfectly-balanced binary subtrees, one per
    /// level, with level `i` holding `4^i` items (1, 4, 16, 64, 256, ...). A uniform
    /// `items_per_chunk`-sized stride only produces valid single-subtree chunks once it's
    /// aligned to these level boundaries, so the first chunk is special: it folds together every
    /// level that fits completely within `items_per_chunk` (e.g. for `items_per_chunk = 32`,
    /// levels 0-2 sum to `1 + 4 + 16 = 21`), and is exactly that folded subtree's root. Every
    /// level from there on is itself at least as large as `items_per_chunk` and an exact
    /// power-of-two multiple of it, so every later chunk can just be a plain, round
    /// `items_per_chunk`-sized slice, no further special-casing needed. Confirmed directly with
    /// Etan Kissling (2026-10-06), who gave this exact rule.
    pub const fn first_chunk_size(self) -> usize {
        first_chunk_size_for(self.items_per_chunk())
    }

    /// Number of chunks a field with `len` items splits into (0 items → 0 chunks).
    ///
    /// The first chunk covers `0..first_chunk_size()` (or the whole field, if it's shorter than
    /// that); every chunk after that is a plain `items_per_chunk()`-sized slice.
    pub fn num_chunks(self, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let first_chunk_size = self.first_chunk_size();
        if len <= first_chunk_size {
            1
        } else {
            1_usize.saturating_add(
                len.saturating_sub(first_chunk_size)
                    .div_ceil(self.items_per_chunk()),
            )
        }
    }

    /// Item-index range covered by the given 0-based chunk index within this field, given the
    /// field's actual `len`. Returns `None` if `local_chunk_index >= num_chunks(len)`.
    pub fn chunk_range(self, len: usize, local_chunk_index: usize) -> Option<Range<usize>> {
        if local_chunk_index >= self.num_chunks(len) {
            return None;
        }
        let first_chunk_size = self.first_chunk_size();
        if local_chunk_index == 0 {
            Some(0..first_chunk_size.min(len))
        } else {
            let items_per_chunk = self.items_per_chunk();
            let start = first_chunk_size.saturating_add(
                local_chunk_index
                    .saturating_sub(1)
                    .saturating_mul(items_per_chunk),
            );
            let end = start.saturating_add(items_per_chunk).min(len);
            Some(start..end)
        }
    }
}

/// The largest `k` such that `4^0 + 4^1 + ... + 4^(k-1) <= items_per_chunk`, returning that sum.
const fn first_chunk_size_for(items_per_chunk: usize) -> usize {
    let mut cumulative = 0usize;
    let mut level_size = 1usize;
    while cumulative.saturating_add(level_size) <= items_per_chunk {
        cumulative = cumulative.saturating_add(level_size);
        level_size = level_size.saturating_mul(4);
    }
    cumulative
}

/// Maps a flat, global `chunk_index` (as used by `beacon_state_parts_by_range`) to the specific
/// field and item-index range within that field the chunk covers, given the actual lengths of
/// every chunked field (from a [`BeaconStateSummary`]'s `ListSummary`s).
///
/// Chunks are laid out as a flat concatenation of each field's chunks, in [`ChunkedField::ALL`]
/// order: all of `historical_roots`'s chunks, then all of `eth1_data_votes`'s, and so on. Within
/// a single field, the first chunk is the irregular [`ChunkedField::first_chunk_size`]-sized one
/// and every chunk after that is a round [`ChunkedField::items_per_chunk`]-sized slice.
#[derive(Debug, Clone)]
pub struct ChunkLayout {
    /// `(field, len, num_chunks, first_global_index)` for each chunked field, in declaration
    /// order. `len` is kept so `locate` can clip the last chunk to the field's actual length.
    per_field: Vec<(ChunkedField, usize, usize, u64)>,
    total_chunks: u64,
}

impl ChunkLayout {
    /// Build a layout from each chunked field's length, in [`ChunkedField::ALL`] order.
    pub fn new(lengths: [usize; 14]) -> Self {
        let mut per_field = Vec::with_capacity(ChunkedField::ALL.len());
        let mut next_chunk_index: u64 = 0;
        for (field, len) in ChunkedField::ALL.into_iter().zip(lengths) {
            let num_chunks = field.num_chunks(len);
            per_field.push((field, len, num_chunks, next_chunk_index));
            next_chunk_index = next_chunk_index.saturating_add(num_chunks as u64);
        }
        Self {
            per_field,
            total_chunks: next_chunk_index,
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
        for &(field, len, num_chunks, first_global_index) in &self.per_field {
            let num_chunks = num_chunks as u64;
            if chunk_index < first_global_index.saturating_add(num_chunks) {
                let local_chunk_index = chunk_index.saturating_sub(first_global_index) as usize;
                return field
                    .chunk_range(len, local_chunk_index)
                    .map(|range| (field, range));
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
    fn first_chunk_size_matches_etans_example() {
        // Etan's own example (2026-10-06): items_per_chunk = 32 folds levels 0-2
        // (1 + 4 + 16 = 21) into the first chunk, since level 3 (64 items) doesn't fit.
        assert_eq!(first_chunk_size_for(32), 21);
    }

    #[test]
    fn first_chunk_size_for_validators() {
        // P = 4096: levels 0-5 (1+4+16+64+256+1024 = 1365) fit; level 6 (4096) doesn't.
        assert_eq!(ChunkedField::Validators.first_chunk_size(), 1365);
    }

    #[test]
    fn num_chunks_accounts_for_irregular_first_chunk() {
        let fc = ChunkedField::Validators.first_chunk_size();
        let per_chunk = ChunkedField::Validators.items_per_chunk();
        assert_eq!(ChunkedField::Validators.num_chunks(fc), 1);
        assert_eq!(ChunkedField::Validators.num_chunks(fc + 1), 2);
        assert_eq!(ChunkedField::Validators.num_chunks(fc + per_chunk), 2);
        assert_eq!(ChunkedField::Validators.num_chunks(fc + per_chunk + 1), 3);
    }

    #[test]
    fn layout_locates_chunks_across_fields() {
        // historical_roots: 0 items -> 0 chunks.
        // eth1_data_votes: 1 item -> 1 chunk, global index 0, entirely within the first chunk.
        // validators: first_chunk_size + items_per_chunk + 1 items -> 3 chunks, global indices
        // 1, 2, 3: the irregular first chunk, one full round chunk, and one trailing 1-item
        // chunk clipped to the field's actual length.
        // everything else: 0 items -> 0 chunks.
        let fc = ChunkedField::Validators.first_chunk_size();
        let per_chunk = ChunkedField::Validators.items_per_chunk();
        let validators_len = fc + per_chunk + 1;
        let lengths = [0, 1, validators_len, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let layout = ChunkLayout::new(lengths);
        assert_eq!(layout.total_chunks(), 4);

        let (field, range) = layout.locate(0).unwrap();
        assert_eq!(field, ChunkedField::Eth1DataVotes);
        assert_eq!(range, 0..1);

        let (field, range) = layout.locate(1).unwrap();
        assert_eq!(field, ChunkedField::Validators);
        assert_eq!(range, 0..fc);

        let (field, range) = layout.locate(2).unwrap();
        assert_eq!(field, ChunkedField::Validators);
        assert_eq!(range, fc..(fc + per_chunk));

        let (field, range) = layout.locate(3).unwrap();
        assert_eq!(field, ChunkedField::Validators);
        assert_eq!(range, (fc + per_chunk)..validators_len);

        assert!(layout.locate(4).is_none());
    }
}
