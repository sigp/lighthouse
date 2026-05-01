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
use types::{
    AbstractExecPayload, BeaconStateError, ColumnIndex, Epoch, EthSpec, Hash256, SignedBeaconBlock,
    SignedExecutionPayloadBid,
};

/// Extract the signed execution payload bid from a Gloas block as a shareable `Arc`.
///
/// Returns `Err` if the block is not a Gloas block.
pub fn signed_payload_bid_from_block<E: EthSpec, P: AbstractExecPayload<E>>(
    block: &SignedBeaconBlock<E, P>,
) -> Result<Arc<SignedExecutionPayloadBid<E>>, BeaconStateError> {
    Ok(Arc::new(
        block
            .message()
            .body()
            .signed_execution_payload_bid()?
            .clone(),
    ))
}

/// This represents the components of a payload pending data availability.
///
/// The columns are all gossip and kzg verified.
/// The payload is considered "available" when all required columns are received.
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub bid: Arc<SignedExecutionPayloadBid<E>>,
    /// a cached post executed payload envelope
    pub envelope: Option<AvailabilityPendingExecutedEnvelope<E>>,
    pub verified_data_columns: HashMap<ColumnIndex, PendingColumn<E>>,
    pub reconstruction_started: bool,
    pub(crate) span: Span,
}

impl<E: EthSpec> PendingComponents<E> {
    pub fn num_blobs_expected(&self) -> usize {
        self.bid.message.blob_kzg_commitments.len()
    }

    /// Returns the completed custody columns
    pub fn get_cached_data_columns(&self) -> Vec<Arc<DataColumnSidecar<E>>> {
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| {
                col.try_to_sidecar(
                    *col_idx,
                    self.bid.message.slot,
                    self.block_root,
                    self.num_blobs_expected(),
                )
            })
            .collect()
    }

    /// Returns the indices of cached custody columns
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| {
                col.is_complete(self.num_blobs_expected())
                    .then_some(*col_idx)
            })
            .collect()
    }

    /// Merges a given set of data columns into the cache.
    pub(crate) fn merge_data_columns(
        &mut self,
        kzg_verified_data_columns: &[KzgVerifiedCustodyDataColumn<E>],
    ) -> Result<(), AvailabilityCheckError> {
        for data_column in kzg_verified_data_columns {
            let data_column = data_column.as_data_column();
            let num_blobs_expected = self.num_blobs_expected();
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

        Ok(())
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
        self.verified_data_columns
            .values()
            .filter_map(|col| col.is_complete(self.num_blobs_expected()).then_some(()))
            .count()
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
            let num_completed_columns = self.num_completed_columns();
            match num_completed_columns.cmp(&num_expected_columns) {
                Ordering::Greater => {
                    // Should never happen
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many columns got {num_completed_columns} expected {num_expected_columns}"
                    )));
                }
                Ordering::Equal => {
                    self.span.in_scope(|| {
                        debug!("All data columns received, data is available");
                    });

                    self.get_cached_data_columns()
                }
                Ordering::Less => {
                    // Not enough data columns received yet
                    return Ok(None);
                }
            }
        };

        let available_envelope = AvailableEnvelope {
            execution_block_hash: envelope.block_hash(),
            envelope: envelope.clone(),
            columns,
            columns_available_timestamp: None,
        };

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

    /// Returns the epoch of the bid or first data column, if available.
    pub fn epoch(&self) -> Epoch {
        self.bid.message.slot.epoch(E::slots_per_epoch())
    }

    pub fn status_str(&self, num_expected_columns: usize) -> String {
        format!(
            "envelope {}, data_columns {}/{}",
            self.envelope.is_some(),
            self.verified_data_columns.len(),
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
