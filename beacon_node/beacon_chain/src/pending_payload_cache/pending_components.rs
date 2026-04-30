use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_column_verification::{
    KzgVerifiedCustodyDataColumn, KzgVerifiedCustodyPartialDataColumnGloas,
};
use crate::payload_envelope_verification::AvailabilityPendingExecutedEnvelope;
use crate::payload_envelope_verification::AvailableEnvelope;
use crate::payload_envelope_verification::AvailableExecutedEnvelope;
use crate::pending_payload_cache::pending_column::PendingColumn;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::DataColumnSidecar;
use types::data::PartialDataColumnGloas;
use types::{ColumnIndex, EthSpec, Hash256, SignedExecutionPayloadBid};

/// This represents the components of a payload pending data availability.
///
/// The columns are all gossip and kzg verified.
/// The payload is considered "available" when all required columns are received.
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub bid: Arc<SignedExecutionPayloadBid<E>>,
    /// a cached post executed payload envelope
    pub envelope: Option<AvailabilityPendingExecutedEnvelope<E>>,
    /// A column entry in this map may only have some cells filled in (i.e. a partial data column)
    pub verified_data_columns: HashMap<ColumnIndex, PendingColumn<E>>,
    pub reconstruction_started: bool,
    /// Set once we have fetched the blobs locally (via `getBlobs` from the EL). Suppresses
    /// republishing partials that would race with the local fetch.
    pub has_local_blobs: bool,
    pub(crate) span: Span,
}

impl<E: EthSpec> PendingComponents<E> {
    pub fn num_blobs_expected(&self) -> usize {
        self.bid.message.blob_kzg_commitments.len()
    }

    /// Returns columns that have all cells present.
    pub fn get_cached_data_columns(&self) -> Vec<Arc<DataColumnSidecar<E>>> {
        let slot = self.bid.message.slot;
        let block_root = self.block_root;
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| col.to_full_sidecar(*col_idx, slot, block_root))
            .collect()
    }

    /// Returns the indices of columns that have all cells present.
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        let slot = self.bid.message.slot;
        let block_root = self.block_root;
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| {
                col.to_full_sidecar(*col_idx, slot, block_root)
                    .map(|_| *col_idx)
            })
            .collect()
    }

    /// Returns all partial (complete and incomplete) columns currently in the cache, suitable for
    /// re-publishing.
    pub(crate) fn get_cached_partial_data_columns(&self) -> Vec<PartialDataColumnGloas<E>> {
        let block_root = self.block_root;
        let slot = self.bid.message.slot;
        self.verified_data_columns
            .iter()
            .filter_map(|(idx, col)| col.to_partial(*idx, slot, block_root))
            .collect()
    }

    /// Merges a given set of data columns into the cache.
    pub(crate) fn merge_data_columns(
        &mut self,
        kzg_verified_data_columns: &[KzgVerifiedCustodyDataColumn<E>],
    ) {
        let num_blobs_expected = self.num_blobs_expected();
        for data_column in kzg_verified_data_columns {
            let data_column = data_column.as_data_column();
            // The Vec-backed `PendingColumn` keys cells by index, so we have to allocate up to
            // `num_blobs_expected` entries before inserting; otherwise `cells.get_mut(idx)` returns
            // None and the insert is a no-op.
            let col = self
                .verified_data_columns
                .entry(*data_column.index())
                .or_insert_with(|| PendingColumn::new_with_capacity(num_blobs_expected));
            for (cell_idx, (cell, proof)) in data_column
                .column()
                .iter()
                .zip(data_column.kzg_proofs().iter())
                .enumerate()
            {
                col.insert(cell_idx, cell, proof);
            }
        }
    }

    /// Merges a given set of partial data columns into the cache.
    pub(crate) fn merge_partial_data_columns(
        &mut self,
        kzg_verified_partial_data_columns: &[KzgVerifiedCustodyPartialDataColumnGloas<E>],
    ) -> PartialColumnsMergeOutcome {
        let num_blobs_expected = self.num_blobs_expected();
        let mut outcome = PartialColumnsMergeOutcome::default();
        for partial in kzg_verified_partial_data_columns {
            let col_index = partial.index();
            let sidecar = partial.sidecar();
            let bitmap = sidecar.cells_present_bitmap();
            let column = sidecar.column();
            let proofs = sidecar.kzg_proofs();

            let was_complete = self
                .verified_data_columns
                .get(&col_index)
                .is_some_and(PendingColumn::is_complete);

            let col = self
                .verified_data_columns
                .entry(col_index)
                .or_insert_with(|| PendingColumn::new_with_capacity(num_blobs_expected));

            let mut storage_idx = 0;
            let mut inserted_cells = 0;
            for (blob_idx, present) in bitmap.iter().enumerate() {
                if !present {
                    continue;
                }
                let (Some(cell), Some(proof)) = (column.get(storage_idx), proofs.get(storage_idx))
                else {
                    break;
                };
                if col.insert(blob_idx, cell, proof) {
                    inserted_cells += 1;
                }
                storage_idx += 1;
            }

            if inserted_cells > 0 {
                outcome.added_cells += inserted_cells;
                outcome.updated.push(col_index);
            }

            if !was_complete && col.is_complete() {
                outcome.newly_complete.push(col_index);
            }
        }
        outcome
    }

    /// Inserts an executed payload envelope into the cache.
    pub fn insert_executed_payload_envelope(
        &mut self,
        envelope: AvailabilityPendingExecutedEnvelope<E>,
    ) {
        self.envelope = Some(envelope);
    }

    pub fn num_completed_columns(&self) -> usize {
        self.get_cached_data_columns().len()
    }

    /// Returns `Some` if the envelope and all required data columns have been received.
    pub fn make_available(
        &self,
        num_expected_columns: usize,
    ) -> Result<Option<AvailableExecutedEnvelope<E>>, AvailabilityCheckError> {
        // Check if the payload has been received and executed
        let Some(envelope) = &self.envelope else {
            return Ok(None);
        };

        let AvailabilityPendingExecutedEnvelope {
            envelope,
            block_root,
            payload_verification_outcome,
        } = envelope;

        let columns = if self.num_blobs_expected() == 0 {
            self.span.in_scope(|| {
                debug!("Bid has no blobs, data is available");
            });
            vec![]
        } else {
            let columns = self.get_cached_data_columns();
            match columns.len().cmp(&num_expected_columns) {
                Ordering::Greater => {
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many columns: got {} expected {num_expected_columns}",
                        columns.len()
                    )));
                }
                Ordering::Equal => {
                    self.span.in_scope(|| {
                        debug!("All data columns received, data is available");
                    });
                    columns
                }
                Ordering::Less => {
                    // Not enough data columns received yet
                    return Ok(None);
                }
            }
        };

        let available_envelope = AvailableEnvelope::new(envelope.clone(), columns);

        Ok(Some(AvailableExecutedEnvelope {
            envelope: available_envelope,
            block_root: *block_root,
            payload_verification_outcome: payload_verification_outcome.clone(),
        }))
    }

    /// Constructs a fresh `PendingComponents` with no envelope and no columns yet.
    pub fn new(block_root: Hash256, bid: Arc<SignedExecutionPayloadBid<E>>) -> Self {
        let span = debug_span!(parent: None, "lh_pending_components", %block_root);
        let _guard = span.clone().entered();
        Self {
            block_root,
            bid,
            envelope: None,
            verified_data_columns: HashMap::new(),
            reconstruction_started: false,
            has_local_blobs: false,
            span,
        }
    }

    pub fn status_str(&self, num_expected_columns: usize) -> String {
        format!(
            "envelope {}, data_columns {}/{}",
            self.envelope.is_some(),
            self.num_completed_columns(),
            num_expected_columns
        )
    }
}

/// Outcome of merging partial data columns into the cache.
#[derive(Default)]
pub(crate) struct PartialColumnsMergeOutcome {
    /// Number of cells newly inserted by the merge (cells already present don't count).
    pub added_cells: usize,
    /// Indices of columns that gained at least one new cell.
    pub updated: Vec<ColumnIndex>,
    /// Indices of columns that became fully populated as a result of the merge.
    pub newly_complete: Vec<ColumnIndex>,
}

// This enum is only used internally within the crate in the reconstruction function to improve
// readability, so it's OK to not box the variant value, and it shouldn't impact memory much with
// the current usage, as it's deconstructed immediately.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReconstructColumnsDecision<E: EthSpec> {
    Yes(Vec<Arc<DataColumnSidecar<E>>>),
    No(&'static str),
}
