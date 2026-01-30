use crate::BeaconChainTypes;
use crate::CustodyContext;
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
    Executed(Box<AvailabilityPendingExecutedPayload<E>>),
}

#[allow(dead_code)]
impl<E: EthSpec> CachedPayload<E> {
    pub fn get_commitments(&self) -> KzgCommitments<E> {
        let payload = self.as_payload();
        payload.message.blob_kzg_commitments.clone()
    }

    fn as_payload(&self) -> &SignedExecutionPayloadEnvelope<E> {
        match self {
            CachedPayload::PreExecution(p, _) => p,
            CachedPayload::Executed(p) => &p.payload,
        }
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.as_payload().message.blob_kzg_commitments.len()
    }

    pub fn payload_cloned(&self) -> Arc<SignedExecutionPayloadEnvelope<E>> {
        match self {
            CachedPayload::PreExecution(p, _) => p.clone(),
            CachedPayload::Executed(p) => p.payload.clone(),
        }
    }
}

/// This represents the components of a partially available payload
///
/// The columns are all gossip and kzg verified.
/// The payload has completed all verifications except the availability check.
#[allow(dead_code)]
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub block: Option<Arc<SignedBeaconBlock<E>>>,
    pub verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
    pub payload: Option<CachedPayload<E>>,
    pub reconstruction_started: bool,
    span: Span,
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

    /// Inserts an executed payload into the cache.
    pub fn insert_executed_payload(&mut self, payload: AvailabilityPendingExecutedPayload<E>) {
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
    pub fn merge_payload(&mut self, payload: AvailabilityPendingExecutedPayload<E>) {
        self.insert_executed_payload(payload);
    }

    /// Returns Some if the payload has received all its required data for import. The return value
    /// must be persisted in the DB along with the payload.
    pub fn make_available(
        &self,
        spec: &Arc<ChainSpec>,
        num_expected_columns: usize,
    ) -> Result<Option<AvailableExecutedPayload<E>>, AvailabilityCheckError> {
        let Some(CachedPayload::Executed(executed_payload)) = &self.payload else {
            // Payload not available yet
            return Ok(None);
        };

        let num_expected_blobs = executed_payload.num_blobs_expected();
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
                    // We have enough columns
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
            return Err(AvailabilityCheckError::Unexpected(
                "Block doesn't exist for the payload being made available".to_owned(),
            ));
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
        } = executed_payload.as_ref().clone();

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
        // Get epoch from cached payload
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
        custody_context: Arc<CustodyContext<T::EthSpec>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            critical: RwLock::new(LruCache::new(capacity)),
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
                            PayloadProcessStatus::ExecutionValidated(p.payload.clone())
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
            // Return `Ok` without marking the payload as available.
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
        if let Some(available_payload) =
            pending_components.make_available(&self.spec, num_expected_columns)?
        {
            // Explicitly drop read lock before acquiring write lock
            drop(pending_components);
            if let Some(components) = self.critical.write().get_mut(&block_root) {
                // Clean up span now that payload is available
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
    ///  - Reconstruction hasn't been started for the payload
    ///
    /// If reconstruction is required, returns `PendingComponents` which contains the
    /// components to be used as inputs to reconstruction, otherwise returns a `reason`.
    pub fn check_and_set_reconstruction_started(
        &self,
        block_root: &Hash256,
    ) -> ReconstructColumnsDecision<T::EthSpec> {
        let mut write_lock = self.critical.write();
        let Some(pending_components) = write_lock.get_mut(block_root) else {
            // Payload may have been imported as it does not exist in availability cache.
            return ReconstructColumnsDecision::No("payload already imported");
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
        // The read lock is immediately dropped so we can safely remove the payload from the cache.
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

        let pending_components =
            self.update_or_insert_pending_components(block_root, |pending_components| {
                pending_components.merge_payload(executed_payload);
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

    /// Number of pending component entries in memory in the cache.
    pub fn payload_cache_size(&self) -> usize {
        self.critical.read().len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::data_column_verification::{GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn};
    use crate::test_utils::generate_data_column_indices_rand_order;
    use crate::{
        block_verification_types::AsBlock,
        custody_context::NodeCustodyType,
        test_utils::{BaseHarnessType, BeaconChainHarness, DiskHarnessType},
    };
    use logging::create_test_tracing_subscriber;
    use std::collections::HashSet;
    use store::{HotColdDB, ItemStore, StoreConfig, database::interface::BeaconNodeBackend};
    use tempfile::{TempDir, tempdir};
    use types::MinimalEthSpec;
    use types::new_non_zero_usize;

    const LOW_VALIDATOR_COUNT: usize = 32;

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
            gloas_head.message().body().execution_payload().is_err(),
            "Gloas block has no payload"
        );
        harness
    }

    async fn availability_pending_payload<E, Hot, Cold>(
        _harness: &BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>,
    ) -> (
        AvailabilityPendingExecutedPayload<E>,
        Vec<GossipVerifiedDataColumn<BaseHarnessType<E, Hot, Cold>>>,
    )
    where
        E: EthSpec,
        Hot: ItemStore<E>,
        Cold: ItemStore<E>,
    {
        todo!()
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
        let _test_store = harness.chain.store.clone();
        let capacity_non_zero = new_non_zero_usize(capacity);
        let custody_context = Arc::new(CustodyContext::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        ));
        let cache = Arc::new(
            DataAvailabilityCheckerInner::<T>::new(capacity_non_zero, custody_context, spec.clone())
                .expect("should create cache"),
        );
        (harness, cache, chain_db_path)
    }

    #[tokio::test]
    #[ignore] // TODO(gloas): Implement availability_pending_payload
    async fn overflow_cache_test_insert_components() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let (pending_payload, columns) = availability_pending_payload(&harness).await;
        let root = pending_payload.as_payload().beacon_block_root();

        let mut expected_column_indices = harness
            .chain
            .data_availability_checker
            .custody_context()
            .custody_columns_for_epoch(None, &harness.chain.spec)
            .iter()
            .collect::<HashSet<_>>();
        let columns_expected = pending_payload.num_blobs_expected();

        assert_eq!(
            columns.len(),
            expected_column_indices.len(),
            "should have expected number of blobs"
        );
        assert!(cache.critical.read().is_empty(), "cache should be empty");
        let availability = cache
            .put_executed_payload(pending_payload)
            .expect("should put payload");
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
            let col_index = gossip_column.index();
            kzg_verified_columns.push(KzgVerifiedCustodyDataColumn::from_asserted_custody(
                gossip_column.into_inner(),
            ));
            let availability = cache
                .put_kzg_verified_data_columns(root, kzg_verified_columns.clone().into_iter())
                .expect("should put column");

            expected_column_indices.remove(&col_index);

            if expected_column_indices.is_empty() {
                assert!(matches!(availability, Availability::Available(_)));
            } else {
                assert!(matches!(availability, Availability::MissingComponents(_)));
                assert_eq!(cache.critical.read().len(), 1);
            }
        }

        let (pending_payload, columns) = availability_pending_payload(&harness).await;
        let expected_column_indices = harness
            .chain
            .data_availability_checker
            .custody_context()
            .custody_columns_for_epoch(None, &harness.chain.spec)
            .iter()
            .collect::<HashSet<_>>();

        assert_eq!(
            columns.len(),
            expected_column_indices.len(),
            "should have expected number of columns"
        );
        let root = pending_payload.as_payload().beacon_block_root();

        let mut kzg_verified_columns = vec![];
        for gossip_column in columns {
            kzg_verified_columns.push(KzgVerifiedCustodyDataColumn::from_asserted_custody(
                gossip_column.into_inner(),
            ));
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
}

#[cfg(test)]
mod pending_components_tests {
    use super::*;
    use crate::PayloadVerificationOutcome;
    use crate::data_column_verification::KzgVerifiedDataColumn;
    use crate::payload_verification_types::PayloadImportData;
    use crate::test_utils::{NumBlobs, generate_rand_payload_and_columns, test_spec};
    use fork_choice::PayloadVerificationStatus;
    use kzg::KzgCommitment;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use ssz_types::VariableList;
    use state_processing::ConsensusContext;
    use types::test_utils::TestRandom;
    use types::{BeaconState, ForkName, MainnetEthSpec, SignedExecutionPayloadEnvelope, Slot};

    type E = MainnetEthSpec;

    type Setup = (
        SignedExecutionPayloadEnvelope<E>,
        DataColumnSidecarList<E>,
        DataColumnSidecarList<E>,
    );

    /// Returns true if gloas is enabled for testing. Tests should skip if this returns false.
    fn is_gloas_enabled() -> bool {
        let spec = test_spec::<E>();
        spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled()
    }

    fn pre_setup() -> Setup {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
        let spec = test_spec::<E>();

        assert!(
            spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled(),
            "pre_setup() only works after gloas"
        );

        let (payload, columns) = generate_rand_payload_and_columns::<E>(
            ForkName::Gloas,
            NumBlobs::Random,
            &mut rng,
            &spec,
        );

        // Create invalid columns by mutating kzg_commitments
        let invalid_columns: DataColumnSidecarList<E> = columns
            .iter()
            .map(|col| {
                let mut col_clone = col.as_ref().clone();
                // Mutate commitments to make them invalid
                let mut commitments: Vec<_> = col_clone.kzg_commitments().iter().copied().collect();
                for commitment in commitments.iter_mut() {
                    *commitment = KzgCommitment::random_for_test(&mut rng);
                }
                let new_commitments =
                    VariableList::try_from(commitments).expect("commitments within bounds");
                match &mut col_clone {
                    DataColumnSidecar::Gloas(gloas) => {
                        gloas.kzg_commitments = new_commitments;
                    }
                    DataColumnSidecar::Fulu(fulu) => {
                        fulu.kzg_commitments = new_commitments;
                    }
                }
                Arc::new(col_clone)
            })
            .collect();

        (payload, columns, invalid_columns)
    }

    type PendingComponentsSetup = (
        AvailabilityPendingExecutedPayload<E>,
        Vec<KzgVerifiedCustodyDataColumn<E>>,
        Vec<KzgVerifiedCustodyDataColumn<E>>,
    );

    fn setup_pending_components(
        payload: SignedExecutionPayloadEnvelope<E>,
        valid_columns: DataColumnSidecarList<E>,
        invalid_columns: DataColumnSidecarList<E>,
    ) -> PendingComponentsSetup {
        let columns: Vec<KzgVerifiedCustodyDataColumn<E>> = valid_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        let invalid_columns: Vec<KzgVerifiedCustodyDataColumn<E>> = invalid_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        let executed_payload = AvailabilityPendingExecutedPayload::new(
            Arc::new(payload.clone()),
            PayloadImportData {
                state: BeaconState::new(0, Default::default(), &test_spec::<E>()),
                consensus_context: ConsensusContext::new(payload.message.slot),
            },
            PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        );

        (executed_payload, columns, invalid_columns)
    }

    fn assert_cache_consistent(cache: &PendingComponents<E>) {
        let cached_payload = cache
            .payload
            .as_ref()
            .expect("expected cached payload to be present");
        let payload_commitments = cached_payload.get_commitments();
        // Each column should have commitments matching the payload
        for col in &cache.verified_data_columns {
            let col_commitments = col.as_data_column().kzg_commitments();
            assert_eq!(
                payload_commitments,
                *col_commitments,
                "column {} commitments should match payload commitments",
                col.index()
            );
        }
    }

    #[allow(dead_code)]
    fn assert_empty_column_cache(cache: &PendingComponents<E>) {
        assert!(
            cache.verified_data_columns.is_empty(),
            "expected empty column cache but found {} columns",
            cache.verified_data_columns.len()
        );
    }

    // v2 merge_data_columns deduplicates by index (first-in wins). When invalid columns
    // are merged first, they persist even after valid columns are merged at the same indices.

    #[test]
    fn payload_invalid_columns_valid_columns() {
        if !is_gloas_enabled() {
            return;
        }
        let (payload, columns, invalid_columns) = pre_setup();
        let (executed_payload, columns, invalid_columns) =
            setup_pending_components(payload, columns, invalid_columns);
        let block_root = Hash256::ZERO;
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_payload(executed_payload);
        cache
            .merge_data_columns(invalid_columns)
            .expect("merge should succeed");
        cache
            .merge_data_columns(columns)
            .expect("merge should succeed");

        // Invalid columns were inserted first, valid columns are deduplicated away.
        // The cache has columns but they have invalid commitments (not matching payload).
        assert!(!cache.verified_data_columns.is_empty());
    }

    #[test]
    fn invalid_columns_payload_valid_columns() {
        if !is_gloas_enabled() {
            return;
        }
        let (payload, columns, invalid_columns) = pre_setup();
        let (executed_payload, columns, invalid_columns) =
            setup_pending_components(payload, columns, invalid_columns);
        let block_root = Hash256::ZERO;
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache
            .merge_data_columns(invalid_columns)
            .expect("merge should succeed");
        cache.merge_payload(executed_payload);
        cache
            .merge_data_columns(columns)
            .expect("merge should succeed");

        // Invalid columns were first, valid ones deduplicated away.
        assert!(!cache.verified_data_columns.is_empty());
    }

    #[test]
    fn invalid_columns_valid_columns_payload() {
        if !is_gloas_enabled() {
            return;
        }
        let (payload, columns, invalid_columns) = pre_setup();
        let (executed_payload, columns, invalid_columns) =
            setup_pending_components(payload, columns, invalid_columns);

        let block_root = Hash256::ZERO;
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache
            .merge_data_columns(invalid_columns)
            .expect("merge should succeed");
        cache
            .merge_data_columns(columns)
            .expect("merge should succeed");
        cache.merge_payload(executed_payload);

        // Invalid columns were first, valid ones deduplicated away.
        assert!(!cache.verified_data_columns.is_empty());
    }

    #[test]
    fn payload_valid_columns_invalid_columns() {
        if !is_gloas_enabled() {
            return;
        }
        let (payload, columns, invalid_columns) = pre_setup();
        let (executed_payload, columns, invalid_columns) =
            setup_pending_components(payload, columns, invalid_columns);

        let block_root = Hash256::ZERO;
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_payload(executed_payload);
        cache
            .merge_data_columns(columns)
            .expect("merge should succeed");
        cache
            .merge_data_columns(invalid_columns)
            .expect("merge should succeed");

        // Valid columns were inserted first, so they persist. Cache should be consistent.
        assert_cache_consistent(&cache);
    }

    #[test]
    fn valid_columns_payload_invalid_columns() {
        if !is_gloas_enabled() {
            return;
        }
        let (payload, columns, invalid_columns) = pre_setup();
        let (executed_payload, columns, invalid_columns) =
            setup_pending_components(payload, columns, invalid_columns);

        let block_root = Hash256::ZERO;
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache
            .merge_data_columns(columns)
            .expect("merge should succeed");
        cache.merge_payload(executed_payload);
        cache
            .merge_data_columns(invalid_columns)
            .expect("merge should succeed");

        // Valid columns were inserted first, so they persist. Cache should be consistent.
        assert_cache_consistent(&cache);
    }

    #[test]
    fn valid_columns_invalid_columns_payload() {
        if !is_gloas_enabled() {
            return;
        }
        let (payload, columns, invalid_columns) = pre_setup();
        let (executed_payload, columns, invalid_columns) =
            setup_pending_components(payload, columns, invalid_columns);

        let block_root = Hash256::ZERO;
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache
            .merge_data_columns(columns)
            .expect("merge should succeed");
        cache
            .merge_data_columns(invalid_columns)
            .expect("merge should succeed");
        cache.merge_payload(executed_payload);

        // Valid columns were inserted first, so they persist. Cache should be consistent.
        assert_cache_consistent(&cache);
    }

    #[test]
    fn should_not_insert_pre_execution_payload_if_executed_payload_exists() {
        if !is_gloas_enabled() {
            return;
        }
        let (payload, _columns, _invalid_columns) = pre_setup();
        let (executed_payload, _columns, _invalid_columns) =
            setup_pending_components(payload.clone(), _columns, _invalid_columns);

        let block_root = Hash256::ZERO;
        let mut pending_component = <PendingComponents<E>>::empty(block_root);

        let pre_execution_payload = Arc::new(payload);
        pending_component
            .insert_pre_execution_payload(pre_execution_payload.clone(), BlockImportSource::Gossip);
        assert!(
            matches!(
                pending_component.payload,
                Some(CachedPayload::PreExecution(_, _))
            ),
            "pre execution payload inserted"
        );

        pending_component.insert_executed_payload(executed_payload);
        assert!(
            matches!(pending_component.payload, Some(CachedPayload::Executed(_))),
            "executed payload inserted"
        );

        pending_component
            .insert_pre_execution_payload(pre_execution_payload, BlockImportSource::Gossip);
        assert!(
            matches!(pending_component.payload, Some(CachedPayload::Executed(_))),
            "executed payload should remain"
        );
    }
}
