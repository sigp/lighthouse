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
use types::{ChainSpec, ColumnIndex, Epoch, EthSpec, Hash256};
use types::{DataColumnSidecar, Slot};

/// This represents the components of a payload pending data availability.
///
/// The columns are all gossip and kzg verified.
/// The payload is considered "available" when all required columns are received.
pub struct PendingComponents<E: EthSpec> {
    pub slot: Slot,
    pub num_blobs_expected: usize,
    /// a cached post executed payload envelope
    pub envelope: Option<AvailabilityPendingExecutedEnvelope<E>>,
    pub verified_data_columns: HashMap<ColumnIndex, PendingColumn<E>>,
    pub reconstruction_started: bool,
    pub(crate) span: Span,
    spec: Arc<ChainSpec>,
}

impl<E: EthSpec> PendingComponents<E> {
    /// Returns the completed custody columns
    pub fn get_cached_data_columns(&self, block_root: Hash256) -> Vec<Arc<DataColumnSidecar<E>>> {
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| {
                col.try_to_sidecar(*col_idx, self.slot, block_root, self.num_blobs_expected)
            })
            .collect()
    }

    /// Returns the indices of cached custody columns
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| {
                col.is_complete(self.num_blobs_expected).then_some(*col_idx)
            })
            .collect()
    }

    /// Merges a given set of data columns into the cache.
    pub(crate) fn merge_data_columns<I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<E>>>(
        &mut self,
        kzg_verified_data_columns: I,
    ) -> Result<(), AvailabilityCheckError> {
        for data_column in kzg_verified_data_columns {
            let data_column = data_column.as_data_column();
            let col = self
                .verified_data_columns
                .entry(*data_column.index())
                .or_insert_with(|| PendingColumn::new_with_capacity(self.num_blobs_expected));
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

    /// Returns the number of blobs expected by reading the bid's kzg commitments.
    /// Returns an error if the bid is not cached. This function should only be called
    /// after ensuring that the bid has been cached.
    pub fn num_blobs_expected(&self) -> usize {
        self.num_blobs_expected
    }

    pub fn num_completed_columns(&self) -> usize {
        self.verified_data_columns
            .values()
            .filter_map(|col| col.is_complete(self.num_blobs_expected).then_some(()))
            .count()
    }

    /// Returns `Some` if the envelope and all required data columns have been received.
    pub fn make_available(
        &self,
        block_hash: Hash256,
        num_expected_columns: usize,
    ) -> Result<Option<AvailableExecutedEnvelope<E>>, AvailabilityCheckError> {
        // Check if the payload has been received and executed
        let Some(envelope) = &self.envelope else {
            return Ok(None);
        };

        let AvailabilityPendingExecutedEnvelope {
            envelope,
            import_data,
            payload_verification_outcome,
        } = envelope;

        let columns = if self.num_blobs_expected == 0 {
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

                    self.verified_data_columns
                        .iter()
                        .filter_map(|(col_idx, col)| {
                            col.try_to_sidecar(
                                *col_idx,
                                self.slot,
                                block_hash,
                                self.num_blobs_expected,
                            )
                        })
                        .collect()
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
            spec: self.spec.clone(),
        };

        Ok(Some(AvailableExecutedEnvelope {
            envelope: available_envelope,
            import_data: import_data.clone(),
            payload_verification_outcome: payload_verification_outcome.clone(),
        }))
    }

    /// Returns an empty `PendingComponents` object with the given block root.
    pub fn empty(
        block_root: Hash256,
        slot: Slot,
        num_blobs_expected: usize,
        spec: Arc<ChainSpec>,
    ) -> Self {
        let span = debug_span!(parent: None, "lh_pending_components", %block_root, %slot);
        let _guard = span.clone().entered();
        Self {
            slot,
            num_blobs_expected,
            envelope: None,
            verified_data_columns: HashMap::new(),
            reconstruction_started: false,
            span,
            spec,
        }
    }

    /// Returns the epoch of the bid or first data column, if available.
    pub fn epoch(&self) -> Epoch {
        self.slot.epoch(E::slots_per_epoch())
    }

    pub fn status_str(&self, num_expected_columns: usize) -> String {
        format!(
            "data_columns {}/{}",
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

/*
#[cfg(test)]
mod pending_components_tests {
    use crate::test_utils::test_spec;

    use super::*;
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;

    #[test]
    fn test_get_cached_data_columns_indices_empty() {
        let spec = Arc::new(test_spec::<E>());
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root, spec);

        let indices = components.get_cached_data_columns_indices();
        assert!(indices.is_empty());
    }

    #[test]
    fn test_status_str_no_bid() {
        let spec = Arc::new(test_spec::<E>());
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root, spec);

        let status = components.status_str(10);
        assert_eq!(status, "data_columns 0/10");
    }

    #[test]
    fn test_num_blobs_expected_no_bid() {
        let spec = Arc::new(test_spec::<E>());
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root, spec);

        let result = components.num_blobs_expected();
        assert!(result.is_err());
        // Error should be AvailabilityCheckError::Unexpected
        assert!(matches!(
            result.unwrap_err(),
            AvailabilityCheckError::Unexpected(_)
        ));
    }

    #[test]
    fn test_make_available_no_bid_returns_none() {
        let spec = Arc::new(test_spec::<E>());
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root, spec);

        // Without a bid, make_available should return Ok(None)
        let result = components.make_available(10);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
*/
