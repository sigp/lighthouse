use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use crate::payload_envelope_verification::AvailabilityPendingExecutedEnvelope;
use crate::payload_envelope_verification::AvailableEnvelope;
use crate::payload_envelope_verification::AvailableExecutedEnvelope;
use std::cmp::Ordering;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::BlockImportSource;
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, Epoch, EthSpec, Hash256, SignedExecutionPayloadBid,
    SignedExecutionPayloadEnvelope,
};

pub enum CachedPayloadEnvelope<E: EthSpec> {
    PreExecution(Arc<SignedExecutionPayloadEnvelope<E>>, BlockImportSource),
    Executed(Box<AvailabilityPendingExecutedEnvelope<E>>),
}

/// This represents the components of a payload pending data availability.
///
/// The columns are all gossip and kzg verified.
/// The payload is considered "available" when all required columns are received.
pub struct PendingComponents<E: EthSpec> {
    /// The execution payload bid containing blob_kzg_commitments.
    pub bid: Option<Arc<SignedExecutionPayloadBid<E>>>,
    /// a cached pre or post executed payload envelope
    pub envelope: Option<CachedPayloadEnvelope<E>>,
    pub verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
    pub reconstruction_started: bool,
    pub(crate) span: Span,
    spec: Arc<ChainSpec>,
}

impl<E: EthSpec> PendingComponents<E> {
    /// Returns an immutable reference to the cached data column.
    pub fn get_cached_data_column(
        &self,
        data_column_index: u64,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        self.verified_data_columns
            .iter()
            .find(|d| d.index() == data_column_index)
            .map(|d| d.clone_arc())
    }

    /// Returns the indices of cached custody columns
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        self.verified_data_columns
            .iter()
            .map(|d| d.index())
            .collect()
    }

    /// Merges a given set of data columns into the cache.
    pub(crate) fn merge_data_columns<I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<E>>>(
        &mut self,
        kzg_verified_data_columns: I,
    ) -> Result<(), AvailabilityCheckError> {
        for data_column in kzg_verified_data_columns {
            if self.get_cached_data_column(data_column.index()).is_none() {
                self.verified_data_columns.push(data_column);
            }
        }

        Ok(())
    }

    /// Inserts an execution payload bid into the cache.
    pub fn insert_bid(&mut self, bid: Arc<SignedExecutionPayloadBid<E>>) {
        self.bid = Some(bid);
    }

    /// Inserts an executed payload envelope into the cache.
    pub fn insert_executed_payload_envelope(
        &mut self,
        envelope: AvailabilityPendingExecutedEnvelope<E>,
    ) {
        self.envelope = Some(CachedPayloadEnvelope::Executed(Box::new(envelope)))
    }

    /// Inserts a pre-executed payload envelope into the cache.
    pub fn insert_pre_executed_payload_envelope(
        &mut self,
        envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
        import_source: BlockImportSource,
    ) {
        self.envelope = Some(CachedPayloadEnvelope::PreExecution(envelope, import_source))
    }

    /// Returns the number of blobs expected by reading the bid's kzg commitments.
    /// Returns an error if the bid is not cached. This function should only be called
    /// after ensuring that the bid has been cached.
    pub fn num_blobs_expected(&self) -> Result<usize, AvailabilityCheckError> {
        let bid = self
            .bid
            .as_ref()
            .ok_or_else(|| AvailabilityCheckError::Unexpected("No bid available".to_string()))?;

        Ok(bid.message.blob_kzg_commitments.len())
    }

    /// Returns `Some` if the envelope and all required data columns have been received.
    pub fn make_available(
        &self,
        num_expected_columns: usize,
    ) -> Result<Option<AvailableExecutedEnvelope<E>>, AvailabilityCheckError> {
        // If no bid has been received, we can start verifying the columns
        if self.bid.is_none() {
            return Ok(None);
        }

        // Check if the payload has been received and executed
        let Some(CachedPayloadEnvelope::Executed(envelope)) = self.envelope.as_ref() else {
            return Ok(None);
        };

        let AvailabilityPendingExecutedEnvelope {
            envelope,
            import_data,
            payload_verification_outcome,
        } = envelope.as_ref();

        // Get the number of blobs expected from the bid
        let num_expected_blobs = self.num_blobs_expected()?;

        let columns = if num_expected_blobs == 0 {
            self.span.in_scope(|| {
                debug!("Bid has no blobs, data is available");
            });
            vec![]
        } else {
            let num_received_columns = self.verified_data_columns.len();
            match num_received_columns.cmp(&num_expected_columns) {
                Ordering::Greater => {
                    // Should never happen
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many columns got {num_received_columns} expected {num_expected_columns}"
                    )));
                }
                Ordering::Equal => {
                    // We have enough columns
                    let data_columns = self
                        .verified_data_columns
                        .iter()
                        .map(|d| d.clone().into_inner())
                        .collect::<Vec<_>>();

                    self.span.in_scope(|| {
                        debug!("All data columns received, data is available");
                    });

                    data_columns
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
    pub fn empty(block_root: Hash256, spec: Arc<ChainSpec>) -> Self {
        let span = debug_span!(parent: None, "lh_pending_components", %block_root);
        let _guard = span.clone().entered();
        Self {
            bid: None,
            envelope: None,
            verified_data_columns: vec![],
            reconstruction_started: false,
            span,
            spec,
        }
    }

    /// Returns the epoch of the bid or first data column, if available.
    pub fn epoch(&self) -> Option<Epoch> {
        // Get epoch from bid
        if let Some(bid) = &self.bid {
            return Some(bid.message.slot.epoch(E::slots_per_epoch()));
        }

        // Or, get epoch from first data column
        if let Some(data_column) = self.verified_data_columns.first() {
            return Some(data_column.as_data_column().epoch());
        }

        None
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
    Yes(Vec<KzgVerifiedCustodyDataColumn<E>>),
    No(&'static str),
}

#[cfg(test)]
mod pending_components_tests {
    use crate::test_utils::test_spec;

    use super::*;
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;

    #[test]
    fn test_empty_pending_components() {
        let spec = Arc::new(test_spec::<E>());
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root, spec);

        assert!(components.bid.is_none());
        assert!(components.verified_data_columns.is_empty());
        assert!(!components.reconstruction_started);
        assert!(components.epoch().is_none());
    }

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
