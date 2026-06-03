use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use crate::payload_envelope_verification::AvailabilityPendingExecutedEnvelope;
use crate::payload_envelope_verification::AvailableEnvelope;
use crate::payload_envelope_verification::AvailableExecutedEnvelope;
use crate::pending_payload_cache::pending_column::PendingColumn;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::DataColumnSidecar;
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

    // TODO(gloas): merge partial columns

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

// This enum is only used internally within the crate in the reconstruction function to improve
// readability, so it's OK to not box the variant value, and it shouldn't impact memory much with
// the current usage, as it's deconstructed immediately.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReconstructColumnsDecision<E: EthSpec> {
    Yes(Vec<Arc<DataColumnSidecar<E>>>),
    No(&'static str),
}
