use super::state_lru_cache::{DietAvailabilityPendingExecutedPayload, StateLRUCache};
use crate::BeaconChainTypes;
use crate::CustodyContext;
use crate::beacon_chain::BeaconStore;
use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_availability_checker_v2::{Availability, AvailablePayload, AvailablePayloadData};
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use crate::payload_verification_types::PayloadProcessStatus;
use crate::payload_verification_types::{
    AvailabilityPendingExecutedPayload, AvailableExecutedPayload,
};
use lru::LruCache;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::cmp::Ordering;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::kzg_ext::KzgCommitments;
use types::{
    BlockImportSource, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch,
    EthSpec, Hash256, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
};

#[derive(Clone)]
pub enum CachedPayload<E: EthSpec> {
    PreExecution(Arc<SignedExecutionPayloadEnvelope<E>>, BlockImportSource),
    Executed(Box<DietAvailabilityPendingExecutedPayload<E>>),
}

impl<E: EthSpec> CachedPayload<E> {
    pub fn get_commitments(&self) -> KzgCommitments<E> {
        let payload = self.as_payload();
        payload.message.blob_kzg_commitments.clone()
    }

    fn as_payload(&self) -> &SignedExecutionPayloadEnvelope<E> {
        match self {
            CachedPayload::PreExecution(p, _) => p,
            CachedPayload::Executed(p) => p.as_payload(),
        }
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.as_payload().message.blob_kzg_commitments.len()
    }
}

/// This represents the components of a partially available payload
///
/// The columns are all gossip and kzg verified.
/// The payload has completed all verifications except the availability check.
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub block: Option<Arc<SignedBeaconBlock<E>>>,
    pub verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
    pub payload: Option<CachedPayload<E>>,
    pub reconstruction_started: bool,
    span: Span,
}

impl<E: EthSpec> PendingComponents<E> {
    #[cfg(test)]
    fn get_diet_payload(&self) -> Option<&DietAvailabilityPendingExecutedPayload<E>> {
        self.payload.as_ref().and_then(|payload| match payload {
            CachedPayload::Executed(payload) => Some(payload.as_ref()),
            _ => None,
        })
    }

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

    /// Inserts an executed payload into the cache.
    pub fn insert_executed_payload(&mut self, payload: DietAvailabilityPendingExecutedPayload<E>) {
        self.payload = Some(CachedPayload::Executed(Box::new(payload)))
    }

    /// Inserts a pre-execution payload into the cache.
    /// This does NOT override an existing executed payload.
    pub fn insert_pre_execution_payload(
        &mut self,
        payload: Arc<SignedExecutionPayloadEnvelope<E>>,
        source: BlockImportSource,
    ) {
        if self.payload.is_none() {
            self.payload = Some(CachedPayload::PreExecution(payload, source))
        }
    }

    /// Merges a given set of data columns into the cache.
    fn merge_data_columns<I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<E>>>(
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

    /// Inserts a new payload.
    pub fn merge_payload(&mut self, payload: DietAvailabilityPendingExecutedPayload<E>) {
        self.insert_executed_payload(payload);
    }

    /// Returns Some if the payload has received all its required data for import. The return value
    /// must be persisted in the DB along with the block.
    ///
    /// WARNING: This function can potentially take a lot of time if the state needs to be
    /// reconstructed from disk. Ensure you are not holding any write locks while calling this.
    pub fn make_available<R>(
        &self,
        spec: &Arc<ChainSpec>,
        num_expected_columns: usize,
        recover: R,
    ) -> Result<Option<AvailableExecutedPayload<E>>, AvailabilityCheckError>
    where
        R: FnOnce(
            DietAvailabilityPendingExecutedPayload<E>,
            &Span,
        ) -> Result<AvailabilityPendingExecutedPayload<E>, AvailabilityCheckError>,
    {
        let Some(CachedPayload::Executed(payload)) = &self.payload else {
            // Payload not available yet
            return Ok(None);
        };

        let num_expected_blobs = payload.num_blobs_expected();
        let column_data = if num_expected_blobs == 0 {
            Some(AvailablePayloadData::NoData)
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
                    // Block is post-peerdas, and we got enough columns
                    let data_columns = self
                        .verified_data_columns
                        .iter()
                        .map(|d| d.clone().into_inner())
                        .collect::<Vec<_>>();
                    Some(AvailablePayloadData::DataColumns(data_columns))
                }
                Ordering::Less => {
                    // Not enough data columns received yet
                    None
                }
            }
        };

        // Payload's data not available yet
        let Some(column_data) = column_data else {
            return Ok(None);
        };

        let Some(block) = self.block.clone() else {
            // This should never happen
            return Err(AvailabilityCheckError::Unexpected(format!(
                "Payload is being made available but no block exists"
            )));
        };

        // Payload is available, construct `AvailableExecutedPayload`

        let payload_available_timestamp = match column_data {
            AvailablePayloadData::NoData => None,
            // TODO(gloas): fix with https://github.com/sigp/lighthouse/issues/7477
            AvailablePayloadData::DataColumns(_) => None,
        };

        let AvailabilityPendingExecutedPayload {
            payload,
            import_data,
            payload_verification_outcome,
        } = recover(*payload.clone(), &self.span)?;

        let available_payload = AvailablePayload {
            block_root: payload.message.beacon_block_root,
            payload,
            block,
            column_data,
            payload_available_timestamp,
            spec: spec.clone(),
        };

        self.span.in_scope(|| {
            debug!("Payload and all data components are available");
        });
        Ok(Some(AvailableExecutedPayload::new(
            available_payload,
            import_data,
            payload_verification_outcome,
        )))
    }

    /// Returns an empty `PendingComponents` object with the given block root.
    pub fn empty(block_root: Hash256) -> Self {
        let span = debug_span!(parent: None, "lh_pending_components", %block_root);
        let _guard = span.clone().entered();
        Self {
            block_root,
            block: None,
            verified_data_columns: vec![],
            payload: None,
            reconstruction_started: false,
            span,
        }
    }

    /// Returns the epoch of:
    /// - The payload if it is cached
    ///   Otherwise, returns None
    pub fn epoch(&self) -> Option<Epoch> {
        // Get epoch from cached block
        if let Some(payload) = &self.payload {
            return Some(
                payload
                    .as_payload()
                    .message
                    .slot
                    .epoch(E::slots_per_epoch()),
            );
        }

        // Or, get epoch from first data column
        if let Some(data_column) = self.verified_data_columns.first() {
            return Some(data_column.as_data_column().epoch());
        }

        None
    }

    pub fn status_str(&self, num_expected_columns: usize) -> String {
        let payload_count = if self.payload.is_some() { 1 } else { 0 };
        format!(
            "payload {} data_columns {}/{}",
            payload_count,
            self.verified_data_columns.len(),
            num_expected_columns
        )
    }
}

/// This is the main struct for this module. Outside methods should
/// interact with the cache through this.
pub struct DataAvailabilityCheckerInner<T: BeaconChainTypes> {
    /// Contains all the data we keep in memory, protected by an RwLock
    critical: RwLock<LruCache<Hash256, PendingComponents<T::EthSpec>>>,
    /// This cache holds a limited number of states in memory and reconstructs them
    /// from disk when necessary. This is necessary until we merge tree-states
    state_cache: StateLRUCache<T>,
    custody_context: Arc<CustodyContext<T::EthSpec>>,
    spec: Arc<ChainSpec>,
}

// This enum is only used internally within the crate in the reconstruction function to improve
// readability, so it's OK to not box the variant value, and it shouldn't impact memory much with
// the current usage, as it's deconstructed immediately.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReconstructColumnsDecision<E: EthSpec> {
    Yes(Vec<KzgVerifiedCustodyDataColumn<E>>),
    No(&'static str),
}

impl<T: BeaconChainTypes> DataAvailabilityCheckerInner<T> {
    pub fn new(
        capacity: NonZeroUsize,
        beacon_store: BeaconStore<T>,
        custody_context: Arc<CustodyContext<T::EthSpec>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            critical: RwLock::new(LruCache::new(capacity)),
            state_cache: StateLRUCache::new(beacon_store, spec.clone()),
            custody_context,
            spec,
        })
    }

    /// Returns true if the payload with the given block root is known, without altering the LRU ordering
    pub fn get_cached_payload(
        &self,
        block_root: &Hash256,
    ) -> Option<PayloadProcessStatus<T::EthSpec>> {
        self.critical
            .read()
            .peek(block_root)
            .and_then(|pending_components| {
                pending_components
                    .payload
                    .as_ref()
                    .map(|payload| match payload {
                        CachedPayload::PreExecution(p, source) => {
                            PayloadProcessStatus::NotValidated(p.clone(), *source)
                        }
                        CachedPayload::Executed(p) => {
                            PayloadProcessStatus::ExecutionValidated(p.payload_cloned())
                        }
                    })
            })
    }

    /// Fetch data columns of a given `block_root` from the cache without affecting the LRU ordering
    pub fn peek_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.critical
            .read()
            .peek(&block_root)
            .map(|pending_components| {
                pending_components
                    .verified_data_columns
                    .iter()
                    .map(|col| col.clone_arc())
                    .collect()
            })
    }

    pub fn peek_pending_components<R, F: FnOnce(Option<&PendingComponents<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        f(self.critical.read().peek(block_root))
    }

    #[allow(clippy::type_complexity)]
    pub fn put_kzg_verified_data_columns<
        I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    >(
        &self,
        block_root: Hash256,
        kzg_verified_data_columns: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut kzg_verified_data_columns = kzg_verified_data_columns.into_iter().peekable();
        let Some(epoch) = kzg_verified_data_columns
            .peek()
            .map(|verified_blob| verified_blob.as_data_column().epoch())
        else {
            // No columns are processed. This can occur if all received columns were filtered out
            // before this point, e.g. due to a CGC change that caused extra columns to be downloaded
            // // before the new CGC took effect.
            // Return `Ok` without marking the block as available.
            return Ok(Availability::MissingComponents(block_root));
        };

        let pending_components = self
            .update_or_insert_pending_components(block_root, |pending_components| {
                pending_components.merge_data_columns(kzg_verified_data_columns)
            })?;

        let num_expected_columns = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "data_columns",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability_and_cache_components(
            block_root,
            pending_components,
            num_expected_columns,
        )
    }

    fn check_availability_and_cache_components(
        &self,
        block_root: Hash256,
        pending_components: MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>,
        num_expected_columns: usize,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if let Some(available_payload) = pending_components.make_available(
            &self.spec,
            num_expected_columns,
            |payload, span| {
                self.state_cache
                    .recover_pending_executed_payload(payload, span)
            },
        )? {
            // Explicitly drop read lock before acquiring write lock
            drop(pending_components);
            if let Some(components) = self.critical.write().get_mut(&block_root) {
                // Clean up span now that block is available
                components.span = Span::none();
            }

            // We never remove the pending components manually to avoid race conditions.
            // This ensures components remain available during and right after payload import,
            // preventing a race condition where a component was removed after the payload was
            // imported, but re-inserted immediately, causing partial pending components to be
            // stored and served to peers.
            // Components are only removed via LRU eviction as finality advances.
            Ok(Availability::Available(Box::new(available_payload)))
        } else {
            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// Updates or inserts a new `PendingComponents` if it doesn't exist, and then apply the
    /// `update_fn` while holding the write lock.
    ///
    /// Once the update is complete, the write lock is downgraded and a read guard with a
    /// reference of the updated `PendingComponents` is returned.
    fn update_or_insert_pending_components<F>(
        &self,
        block_root: Hash256,
        update_fn: F,
    ) -> Result<MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>, AvailabilityCheckError>
    where
        F: FnOnce(&mut PendingComponents<T::EthSpec>) -> Result<(), AvailabilityCheckError>,
    {
        let mut write_lock = self.critical.write();

        {
            let pending_components =
                write_lock.get_or_insert_mut(block_root, || PendingComponents::empty(block_root));
            update_fn(pending_components)?
        }

        RwLockReadGuard::try_map(RwLockWriteGuard::downgrade(write_lock), |cache| {
            cache.peek(&block_root)
        })
        .map_err(|_| {
            AvailabilityCheckError::Unexpected("pending components should exist".to_string())
        })
    }

    /// Check whether data column reconstruction should be attempted.
    ///
    /// Potentially trigger reconstruction if all the following satisfy:
    ///  - Our custody requirement is more than 50% of total columns,
    ///  - We haven't received all required columns
    ///  - Reconstruction hasn't been started for the block
    ///
    /// If reconstruction is required, returns `PendingComponents` which contains the
    /// components to be used as inputs to reconstruction, otherwise returns a `reason`.
    pub fn check_and_set_reconstruction_started(
        &self,
        block_root: &Hash256,
    ) -> ReconstructColumnsDecision<T::EthSpec> {
        let mut write_lock = self.critical.write();
        let Some(pending_components) = write_lock.get_mut(block_root) else {
            // Block may have been imported as it does not exist in availability cache.
            return ReconstructColumnsDecision::No("block already imported");
        };

        let Some(epoch) = pending_components
            .verified_data_columns
            .first()
            .map(|c| c.as_data_column().epoch())
        else {
            return ReconstructColumnsDecision::No("not enough columns");
        };

        let total_column_count = T::EthSpec::number_of_columns();
        let sampling_column_count = self
            .custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec);
        let received_column_count = pending_components.verified_data_columns.len();

        if pending_components.reconstruction_started {
            return ReconstructColumnsDecision::No("already started");
        }
        if received_column_count >= sampling_column_count {
            return ReconstructColumnsDecision::No("all sampling columns received");
        }
        if received_column_count < total_column_count / 2 {
            return ReconstructColumnsDecision::No("not enough columns");
        }

        pending_components.reconstruction_started = true;
        ReconstructColumnsDecision::Yes(pending_components.verified_data_columns.clone())
    }

    /// This could mean some invalid data columns made it through to the `DataAvailabilityChecker`.
    /// In this case, we remove all data columns in `PendingComponents`, reset reconstruction
    /// status so that we can attempt to retrieve columns from peers again.
    pub fn handle_reconstruction_failure(&self, block_root: &Hash256) {
        if let Some(pending_components_mut) = self.critical.write().get_mut(block_root) {
            pending_components_mut.verified_data_columns = vec![];
            pending_components_mut.reconstruction_started = false;
        }
    }

    /// Inserts a pre executed payload into the cache.
    /// - This does NOT trigger the availability check as the payload still needs to be executed.
    /// - This does NOT override an existing cached payload to avoid overwriting an executed payload.
    pub fn put_pre_execution_payload(
        &self,
        block_root: Hash256,
        payload: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        source: BlockImportSource,
    ) -> Result<(), AvailabilityCheckError> {
        let epoch = payload.message.slot.epoch(T::EthSpec::slots_per_epoch());
        let pending_components =
            self.update_or_insert_pending_components(block_root, |pending_components| {
                pending_components.insert_pre_execution_payload(payload, source);
                Ok(())
            })?;

        let num_expected_columns_opt = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "pre execution payload",
                status = pending_components.status_str(num_expected_columns_opt),
                "Component added to data availability checker"
            );
        });

        Ok(())
    }

    /// Removes a pre-execution payload from the cache.
    /// This does NOT remove an existing executed payload.
    pub fn remove_pre_execution_payload(&self, block_root: &Hash256) {
        // The read lock is immediately dropped so we can safely remove the block from the cache.
        if let Some(PayloadProcessStatus::NotValidated(_, _)) = self.get_cached_payload(block_root)
        {
            self.critical.write().pop(block_root);
        }
    }

    /// Check if we have all the columns for a payload. If we do, return the Availability variant that
    /// triggers import of the payload.
    pub fn put_executed_payload(
        &self,
        executed_payload: AvailabilityPendingExecutedPayload<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = executed_payload
            .as_payload()
            .message
            .slot
            .epoch(T::EthSpec::slots_per_epoch());
        let block_root = executed_payload.payload.message.beacon_block_root;

        // register the payload to get the diet block
        let diet_executed_payload = self
            .state_cache
            .register_pending_executed_payload(executed_payload);

        let pending_components =
            self.update_or_insert_pending_components(block_root, |pending_components| {
                pending_components.merge_payload(diet_executed_payload);
                Ok(())
            })?;

        let num_expected_columns = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "payload",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability_and_cache_components(
            block_root,
            pending_components,
            num_expected_columns,
        )
    }

    fn get_num_expected_columns(&self, epoch: Epoch) -> usize {
        self.custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec)
    }

    /// maintain the cache
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // clean up any lingering states in the state cache
        self.state_cache.do_maintenance(cutoff_epoch);

        // Collect keys of pending payloads from a previous epoch to cutoff
        let mut write_lock = self.critical.write();
        let mut keys_to_remove = vec![];
        for (key, value) in write_lock.iter() {
            if let Some(epoch) = value.epoch()
                && epoch < cutoff_epoch
            {
                keys_to_remove.push(*key);
            }
        }
        // Now remove keys
        for key in keys_to_remove {
            write_lock.pop(&key);
        }

        Ok(())
    }

    #[cfg(test)]
    /// get the state cache for inspection (used only for tests)
    pub fn state_lru_cache(&self) -> &StateLRUCache<T> {
        &self.state_cache
    }

    /// Number of states stored in memory in the cache.
    pub fn state_cache_size(&self) -> usize {
        self.state_cache.lru_cache().read().len()
    }

    /// Number of pending component entries in memory in the cache.
    pub fn payload_cache_size(&self) -> usize {
        self.critical.read().len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::data_column_verification::GossipVerifiedDataColumn;
    use crate::payload_verification_types::PayloadImportData;
    use crate::test_utils::generate_data_column_indices_rand_order;
    use crate::{
        block_verification::PayloadVerificationOutcome,
        block_verification_types::{AsBlock, BlockImportData},
        custody_context::NodeCustodyType,
        data_availability_checker_v2::STATE_LRU_CAPACITY_NON_ZERO,
        test_utils::{BaseHarnessType, BeaconChainHarness, DiskHarnessType},
    };
    use fork_choice::PayloadVerificationStatus;
    use logging::create_test_tracing_subscriber;
    use state_processing::ConsensusContext;
    use std::collections::{HashSet, VecDeque};
    use store::{HotColdDB, ItemStore, StoreConfig, database::interface::BeaconNodeBackend};
    use tempfile::{TempDir, tempdir};
    use tracing::{debug_span, info};
    use types::new_non_zero_usize;
    use types::{ExecPayload, MinimalEthSpec};

    const LOW_VALIDATOR_COUNT: usize = 32;
    const STATE_LRU_CAPACITY: usize = STATE_LRU_CAPACITY_NON_ZERO.get();

    fn get_store_with_spec<E: EthSpec>(
        db_path: &TempDir,
        spec: Arc<ChainSpec>,
    ) -> Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>> {
        let hot_path = db_path.path().join("hot_db");
        let cold_path = db_path.path().join("cold_db");
        let blobs_path = db_path.path().join("blobs_db");
        let config = StoreConfig::default();

        HotColdDB::open(
            &hot_path,
            &cold_path,
            &blobs_path,
            |_, _, _| Ok(()),
            config,
            spec,
        )
        .expect("disk store should initialize")
    }
    async fn get_gloas_chain<E: EthSpec>(
        db_path: &TempDir,
    ) -> BeaconChainHarness<DiskHarnessType<E>> {
        let altair_fork_epoch = Epoch::new(0);
        let bellatrix_fork_epoch = Epoch::new(0);
        let capella_fork_epoch = Epoch::new(0);
        let deneb_fork_epoch = Epoch::new(0);
        let electra_fork_epoch = Epoch::new(0);
        let fulu_fork_epoch = Epoch::new(0);
        let gloas_fork_epoch = Epoch::new(0);

        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(altair_fork_epoch);
        spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
        spec.capella_fork_epoch = Some(capella_fork_epoch);
        spec.deneb_fork_epoch = Some(deneb_fork_epoch);
        spec.electra_fork_epoch = Some(electra_fork_epoch);
        spec.fulu_fork_epoch = Some(fulu_fork_epoch);
        spec.gloas_fork_epoch = Some(gloas_fork_epoch);
        let spec = Arc::new(spec);

        let chain_store = get_store_with_spec::<E>(db_path, spec.clone());
        let validators_keypairs =
            types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .keypairs(validators_keypairs)
            .fresh_disk_store(chain_store)
            .mock_execution_layer()
            .build();

        // go to gloas slot
        let gloas_fork_slot = gloas_fork_epoch.start_slot(E::slots_per_epoch());
        harness.extend_to_slot(gloas_fork_slot).await;
        let gloas_head = &harness.chain.head_snapshot().beacon_block;
        assert!(gloas_head.as_gloas().is_ok());
        assert_eq!(gloas_head.slot(), gloas_fork_slot);
        assert!(
            gloas_head
                .message()
                .body()
                .execution_payload()
                .is_err(),
            "Gloas block has no payload"
        );
        harness
    }

    async fn availability_pending_payload<E, Hot, Cold>(
        harness: &BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>,
    ) -> (
        AvailabilityPendingExecutedPayload<E>,
        Vec<GossipVerifiedDataColumn<BaseHarnessType<E, Hot, Cold>>>,
    )
    where
        E: EthSpec,
        Hot: ItemStore<E>,
        Cold: ItemStore<E>,
    {
        let chain = &harness.chain;
        let head = chain.head_snapshot();
        let parent_state = head.beacon_state.clone();

        let target_slot = chain.slot().expect("should get slot") + 1;
        let parent_root = head.beacon_block_root;
        let parent_block = chain
            .get_payload(&parent_root)
            .expect("should get block")
            .expect("should have block");


        let (signed_beacon_block_hash, (block, maybe_blobs), state) = harness
            .add_block_at_slot(target_slot, parent_state)
            .await
            .expect("should add block");
        let block_root = signed_beacon_block_hash.into();
        assert_eq!(
            block_root,
            block.canonical_root(),
            "block root should match"
        );

        // log kzg commitments
        info!("printing kzg commitments");
        for comm in Vec::from(
            block
                .message()
                .body()
                .blob_kzg_commitments()
                .expect("should be deneb fork")
                .clone(),
        ) {
            info!(commitment = ?comm, "kzg commitment");
        }
        info!("done printing kzg commitments");

        let gossip_verified_columns = if let Some((kzg_proofs, blobs)) = maybe_blobs {
            let sidecars =
                DataColumnSidecar::build_sidecars(blobs, &block, &chain.kzg, &chain.spec).unwrap();
            Vec::from(sidecars)
                .into_iter()
                .map(|sidecar| {
                    let subnet = *sidecar.index();
                    GossipVerifiedDataColumn::new(sidecar, subnet.into(), &harness.chain)
                        .expect("should validate column")
                })
                .collect()
        } else {
            vec![]
        };

        let slot = block.slot();
        let consensus_context: ConsensusContext<E> = ConsensusContext::<E>::new(slot);
        let import_data: PayloadImportData<E> = PayloadImportData {
            state,
            consensus_context,
        };

        let payload_verification_outcome = PayloadVerificationOutcome {
            payload_verification_status: PayloadVerificationStatus::Verified,
            is_valid_merge_transition_block: false,
        };

        let availability_pending_block = AvailabilityPendingExecutedPayload {
            payload,
            import_data,
            payload_verification_outcome,
        };

        (availability_pending_block, gossip_verified_columns)
    }

    async fn setup_harness_and_cache<E, T>(
        capacity: usize,
    ) -> (
        BeaconChainHarness<DiskHarnessType<E>>,
        Arc<DataAvailabilityCheckerInner<T>>,
        TempDir,
    )
    where
        E: EthSpec,
        T: BeaconChainTypes<
                HotStore = BeaconNodeBackend<E>,
                ColdStore = BeaconNodeBackend<E>,
                EthSpec = E,
            >,
    {
        create_test_tracing_subscriber();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness = get_gloas_chain(&chain_db_path).await;
        let spec = harness.spec.clone();
        let test_store = harness.chain.store.clone();
        let capacity_non_zero = new_non_zero_usize(capacity);
        let custody_context = Arc::new(CustodyContext::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        ));
        let cache = Arc::new(
            DataAvailabilityCheckerInner::<T>::new(
                capacity_non_zero,
                test_store,
                custody_context,
                spec.clone(),
            )
            .expect("should create cache"),
        );
        (harness, cache, chain_db_path)
    }

    #[tokio::test]
    async fn overflow_cache_test_insert_components() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let (pending_payload, columns) = availability_pending_payload(&harness).await;
        let root = pending_payload.as_payload().beacon_block_root();

        let expected_column_indices = harness.chain.data_availability_checker.custody_context().custody_columns_for_epoch(None, &harness.chain.spec).iter().collect::<HashSet<_>>();
        let columns_expected = pending_payload.num_blobs_expected();

        assert_eq!(
            columns.len(),
            expected_column_indices.len(),
            "should have expected number of blobs"
        );
        assert!(cache.critical.read().is_empty(), "cache should be empty");
        let availability = cache
            .put_executed_payload(pending_payload)
            .expect("should put block");
        if columns_expected == 0 {
            assert!(
                matches!(availability, Availability::Available(_)),
                "payload doesn't have columns, should be available"
            );
            assert_eq!(
                cache.critical.read().len(),
                1,
                "cache should still have payload as it hasn't been imported yet"
            );
        } else {
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending columns"
            );
            assert_eq!(
                cache.critical.read().len(),
                1,
                "cache should have one payload"
            );
            assert!(
                cache.critical.read().peek(&root).is_some(),
                "newly inserted payload should exist in memory"
            );
        }

        let mut kzg_verified_columns = Vec::new();

        for gossip_column in columns.into_iter() {
            kzg_verified_columns.push(gossip_column.into_inner());
            let availability = cache
                .put_kzg_verified_data_columns(root, kzg_verified_columns.clone().into_iter())
                .expect("should put column");

            expected_column_indices.remove(&gossip_column.index());

            if expected_column_indices.is_empty() {
                assert!(matches!(availability, Availability::Available(_)));
            } else {
                assert!(matches!(availability, Availability::MissingComponents(_)));
                assert_eq!(cache.critical.read().len(), 1);
            }
        }

        let (pending_payload, columns) = availability_pending_payload(&harness).await;
        let expected_column_indices = harness.chain.data_availability_checker.custody_context().custody_columns_for_epoch(None, &harness.chain.spec).iter().collect::<HashSet<_>>();
        let columns_expected = pending_payload.num_blobs_expected();
        assert_eq!(
            columns.len(),
            expected_column_indices.len(),
            "should have expected number of blobs"
        );
        let root = pending_payload.as_payload().beacon_block_root();

        let mut kzg_verified_columns = vec![];
        for gossip_column in columns {
            kzg_verified_columns.push(gossip_column.into_inner());
            let availability = cache
                .put_kzg_verified_data_columns(root, kzg_verified_columns.clone())
                .expect("should put column");
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending payload"
            );
            assert_eq!(
                cache.critical.read().len(),
                2,
                "cache should have two payloads now"
            );
        }
        let availability = cache
            .put_executed_payload(pending_payload)
            .expect("should put payload");
        assert!(
            matches!(availability, Availability::Available(_)),
            "payload should be available: {:?}",
            availability
        );
        assert!(
            cache.critical.read().len() == 2,
            "cache should still have available payload"
        );
    }

    #[tokio::test]
    // ensure the state cache keeps memory usage low and that it can properly recover states
    // THIS TEST CAN BE DELETED ONCE TREE STATES IS MERGED AND WE RIP OUT THE STATE CACHE
    async fn overflow_cache_test_state_cache() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = STATE_LRU_CAPACITY * 2;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let mut pending_blocks = VecDeque::new();
        let mut states = Vec::new();
        let mut state_roots = Vec::new();
        // Get enough blocks to fill the cache to capacity, ensuring all blocks have blobs
        while pending_blocks.len() < capacity {
            let (mut pending_block, _) = availability_pending_block(&harness).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let state_root = pending_block.import_data.state.canonical_root().unwrap();
            states.push(pending_block.import_data.state.clone());
            pending_blocks.push_back(pending_block);
            state_roots.push(state_root);
        }

        let state_cache = cache.state_lru_cache().lru_cache();
        let mut pushed_diet_blocks = VecDeque::new();

        for i in 0..capacity {
            let pending_block = pending_blocks.pop_front().expect("should have block");
            let block_root = pending_block.as_block().canonical_root();

            assert_eq!(
                state_cache.read().len(),
                std::cmp::min(i, STATE_LRU_CAPACITY),
                "state cache should be empty at start"
            );

            if i >= STATE_LRU_CAPACITY {
                let lru_root = state_roots[i - STATE_LRU_CAPACITY];
                assert_eq!(
                    state_cache.read().peek_lru().map(|(root, _)| root),
                    Some(&lru_root),
                    "lru block should be in cache"
                );
            }

            // put the block in the cache
            let availability = cache
                .put_executed_block(pending_block)
                .expect("should put block");

            // grab the diet block from the cache for later testing
            let diet_block = cache
                .critical
                .read()
                .peek(&block_root)
                .and_then(|pending_components| pending_components.get_diet_block().cloned())
                .expect("should exist");
            pushed_diet_blocks.push_back(diet_block);

            // should be unavailable since we made sure all blocks had blobs
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending blobs"
            );

            if i >= STATE_LRU_CAPACITY {
                let evicted_index = i - STATE_LRU_CAPACITY;
                let evicted_root = state_roots[evicted_index];
                assert!(
                    state_cache.read().peek(&evicted_root).is_none(),
                    "lru root should be evicted"
                );
                // get the diet block via direct conversion (testing only)
                let diet_block = pushed_diet_blocks.pop_front().expect("should have block");
                // reconstruct the pending block by replaying the block on the parent state
                let recovered_pending_block = cache
                    .state_lru_cache()
                    .recover_pending_executed_block(diet_block, &debug_span!("test"))
                    .expect("should reconstruct pending block");

                // assert the recovered state is the same as the original
                assert_eq!(
                    recovered_pending_block.import_data.state, states[evicted_index],
                    "recovered state should be the same as the original"
                );
            }
        }

        // now check the last block
        let last_block = pushed_diet_blocks.pop_back().expect("should exist").clone();
        // the state should still be in the cache
        assert!(
            state_cache
                .read()
                .peek(&last_block.as_block().state_root())
                .is_some(),
            "last block state should still be in cache"
        );
        // get the diet block via direct conversion (testing only)
        let diet_block = last_block.clone();
        // recover the pending block from the cache
        let recovered_pending_block = cache
            .state_lru_cache()
            .recover_pending_executed_block(diet_block, &debug_span!("test"))
            .expect("should reconstruct pending block");
        // assert the recovered state is the same as the original
        assert_eq!(
            Some(&recovered_pending_block.import_data.state),
            states.last(),
            "recovered state should be the same as the original"
        );
    }
}

#[cfg(test)]
mod pending_components_tests {
    use super::*;
    use crate::PayloadVerificationOutcome;
    use crate::payload_verification_types::PayloadImportData;
    use crate::test_utils::{NumBlobs, generate_rand_block_and_blobs, test_spec};
    use fixed_bytes::FixedBytesExtended;
    use fork_choice::PayloadVerificationStatus;
    use kzg::KzgCommitment;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use state_processing::ConsensusContext;
    use types::test_utils::TestRandom;
    use types::{BeaconState, ForkName, MainnetEthSpec, SignedBeaconBlock, Slot};

    type E = MainnetEthSpec;

    type Setup<E> = (
        SignedBeaconBlock<E>,
        RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        usize,
    );

    pub fn pre_setup() -> Setup<E> {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
        let spec = test_spec::<E>();
        let (block, blobs_vec) =
            generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Random, &mut rng);
        let max_len = spec.max_blobs_per_block(block.epoch()) as usize;
        let mut blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>> =
            RuntimeFixedVector::default(max_len);

        for blob in blobs_vec {
            if let Some(b) = blobs.get_mut(blob.index as usize) {
                *b = Some(Arc::new(blob));
            }
        }

        let mut invalid_blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>> =
            RuntimeFixedVector::default(max_len);
        for (index, blob) in blobs.iter().enumerate() {
            if let Some(invalid_blob) = blob {
                let mut blob_copy = invalid_blob.as_ref().clone();
                blob_copy.kzg_commitment = KzgCommitment::random_for_test(&mut rng);
                *invalid_blobs.get_mut(index).unwrap() = Some(Arc::new(blob_copy));
            }
        }

        (block, blobs, invalid_blobs, max_len)
    }

    type PendingComponentsSetup<E> = (
        DietAvailabilityPendingExecutedBlock<E>,
        RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
        RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
    );

    pub fn setup_pending_components(
        payload: SignedExecutionPayloadEnvelope<E>,
        valid_columns: RuntimeFixedVector<Option<Arc<DataColumnSidecar<E>>>>,
        invalid_columns: RuntimeFixedVector<Option<Arc<DataColumnSidecar<E>>>>,
    ) -> PendingComponentsSetup<E> {
        let columns = RuntimeFixedVector::new(
            valid_columns
                .iter()
                .map(|column_opt| {
                    column_opt
                        .as_ref()
                        .map(|column| KzgVerifiedDataColumn::__assumed_valid(column.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let invalid_columns = RuntimeFixedVector::new(
            invalid_columns
                .iter()
                .map(|column_opt| {
                    column_opt
                        .as_ref()
                        .map(|column| KzgVerifiedDataColumn::__assumed_valid(column.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let block = AvailabilityPendingExecutedBlock {
            payload: Arc::new(payload),
            import_data: PayloadImportData {
                state: BeaconState::new(0, Default::default(), &ChainSpec::minimal()),
                consensus_context: ConsensusContext::new(Slot::new(0)),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        };
        (payload, columns, invalid_blobs)
    }

    pub fn assert_cache_consistent(cache: PendingComponents<E>, max_len: usize) {
        if let Some(cached_payload) = &cache.payload {
            let cached_payload_commitments = cached_payload.get_commitments();
            for index in 0..max_len {
                let payload_commitment = cached_payload_commitments.get(index).copied();
                let column_commitment_opt = cache.get_cached_data_column().get(index).unwrap();
                let column_commitment = column_commitment_opt.as_ref().map(|c| *c.get_commitment());
                assert_eq!(payload_commitment, column_commitment);
            }
        } else {
            panic!("No cached payload")
        }
    }

    pub fn assert_empty_column_cache(cache: PendingComponents<E>) {
        for column_indices in cache.get_cached_data_columns_indices().iter() {
            panic!("assert_empty_column_cache failed");
        }
    }

    #[test]
    fn valid_block_invalid_blobs_valid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn invalid_blobs_block_valid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn invalid_blobs_valid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);

        assert_empty_blob_cache(cache);
    }

    #[test]
    fn block_valid_blobs_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn valid_blobs_block_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn valid_blobs_invalid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn should_not_insert_pre_execution_block_if_executed_block_exists() {
        let (pre_execution_block, blobs, random_blobs, max_len) = pre_setup();
        let (executed_block, _blobs, _random_blobs) =
            setup_pending_components(pre_execution_block.clone(), blobs, random_blobs);

        let block_root = pre_execution_block.canonical_root();
        let mut pending_component = <PendingComponents<E>>::empty(block_root, max_len);

        let pre_execution_block = Arc::new(pre_execution_block);
        pending_component
            .insert_pre_execution_block(pre_execution_block.clone(), BlockImportSource::Gossip);
        assert!(
            matches!(
                pending_component.block,
                Some(CachedBlock::PreExecution(_, _))
            ),
            "pre execution block inserted"
        );

        pending_component.insert_executed_block(executed_block);
        assert!(
            matches!(pending_component.block, Some(CachedBlock::Executed(_))),
            "executed block inserted"
        );

        pending_component
            .insert_pre_execution_block(pre_execution_block, BlockImportSource::Gossip);
        assert!(
            matches!(pending_component.block, Some(CachedBlock::Executed(_))),
            "executed block should remain"
        );
    }
}
