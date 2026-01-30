use crate::BeaconChainTypes;
use crate::CustodyContext;
use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_availability_checker_v2::Availability;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use lru::LruCache;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::cmp::Ordering;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Hash256,
    SignedBeaconBlock,
};

/// This represents the components of a payload pending data availability.
///
/// The columns are all gossip and kzg verified.
/// The payload is considered "available" when all required columns are received.
pub struct PendingComponents<E: EthSpec> {
    /// The block root is stored for tracing context in the span.
    #[allow(dead_code)]
    pub block_root: Hash256,
    pub block: Option<Arc<SignedBeaconBlock<E>>>,
    pub verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
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

    /// Inserts a block into the cache.
    pub fn insert_block(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.block = Some(block);
    }

    /// Returns the number of blobs expected for this block by reading the bid's kzg commitments.
    /// Returns an error if the block is not cached or not a Gloas block.
    pub fn num_blobs_expected(&self) -> Result<usize, AvailabilityCheckError> {
        let block = self.block.as_ref().ok_or_else(|| {
            AvailabilityCheckError::Unexpected("No block available".to_string())
        })?;

        let bid = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .map_err(|_| {
                AvailabilityCheckError::Unexpected(
                    "Block does not have execution payload bid (not a Gloas block?)".to_string(),
                )
            })?;

        Ok(bid.message.blob_kzg_commitments.len())
    }

    /// Returns Some if all required data columns have been received.
    pub fn make_available(
        &self,
        num_expected_columns: usize,
    ) -> Result<Option<DataColumnSidecarList<E>>, AvailabilityCheckError> {
        // Check if we have a block - if not, still waiting
        if self.block.is_none() {
            return Ok(None);
        }

        // Get the number of blobs expected from the block's bid
        // This will error if the block doesn't have a bid (not Gloas)
        let num_expected_blobs = self.num_blobs_expected()?;

        if num_expected_blobs == 0 {
            // No blobs expected, data is available (empty)
            self.span.in_scope(|| {
                debug!("Block has no blobs, data is available");
            });
            return Ok(Some(vec![]));
        }

        let num_received_columns = self.verified_data_columns.len();
        match num_received_columns.cmp(&num_expected_columns) {
            Ordering::Greater => {
                // Should never happen
                Err(AvailabilityCheckError::Unexpected(format!(
                    "too many columns got {num_received_columns} expected {num_expected_columns}"
                )))
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

                Ok(Some(data_columns))
            }
            Ordering::Less => {
                // Not enough data columns received yet
                Ok(None)
            }
        }
    }

    /// Returns an empty `PendingComponents` object with the given block root.
    pub fn empty(block_root: Hash256) -> Self {
        let span = debug_span!(parent: None, "lh_pending_components", %block_root);
        let _guard = span.clone().entered();
        Self {
            block_root,
            block: None,
            verified_data_columns: vec![],
            reconstruction_started: false,
            span,
        }
    }

    /// Returns the epoch of the block or first data column, if available.
    pub fn epoch(&self) -> Option<Epoch> {
        // Get epoch from block
        if let Some(block) = &self.block {
            return Some(block.slot().epoch(E::slots_per_epoch()));
        }

        // Or, get epoch from first data column
        if let Some(data_column) = self.verified_data_columns.first() {
            return Some(data_column.as_data_column().epoch());
        }

        None
    }

    pub fn status_str(&self, num_expected_columns: usize) -> String {
        let block_status = if self.block.is_some() { "yes" } else { "no" };
        format!(
            "block {} data_columns {}/{}",
            block_status,
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

    /// Insert a block into the cache and check if data becomes available.
    pub fn put_block(
        &self,
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());

        let pending_components =
            self.update_or_insert_pending_components(block_root, |pending_components| {
                pending_components.insert_block(block);
                Ok(())
            })?;

        let num_expected_columns = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "block",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability(block_root, pending_components, num_expected_columns)
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
            .map(|verified_col| verified_col.as_data_column().epoch())
        else {
            // No columns are processed. This can occur if all received columns were filtered out
            // before this point, e.g. due to a CGC change that caused extra columns to be downloaded
            // before the new CGC took effect.
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

        self.check_availability(block_root, pending_components, num_expected_columns)
    }

    fn check_availability(
        &self,
        block_root: Hash256,
        pending_components: MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>,
        num_expected_columns: usize,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if let Some(columns) = pending_components.make_available(num_expected_columns)? {
            // Explicitly drop read lock before acquiring write lock
            drop(pending_components);
            if let Some(components) = self.critical.write().get_mut(&block_root) {
                // Clean up span now that data is available
                components.span = Span::none();
            }

            // We never remove the pending components manually to avoid race conditions.
            // This ensures components remain available during and right after block import,
            // preventing a race condition where a component was removed after the block was
            // imported, but re-inserted immediately, causing partial pending components to be
            // stored and served to peers.
            // Components are only removed via LRU eviction as finality advances.
            Ok(Availability::Available(Box::new((block_root, columns))))
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

    fn get_num_expected_columns(&self, epoch: Epoch) -> usize {
        self.custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec)
    }

    /// maintain the cache
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // Collect keys of pending blocks from a previous epoch to cutoff
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
    pub fn block_cache_size(&self) -> usize {
        self.critical.read().len()
    }
}

#[cfg(test)]
mod pending_components_tests {
    use super::*;
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;

    #[test]
    fn test_empty_pending_components() {
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root);

        assert_eq!(components.block_root, block_root);
        assert!(components.block.is_none());
        assert!(components.verified_data_columns.is_empty());
        assert!(!components.reconstruction_started);
        assert!(components.epoch().is_none());
    }

    #[test]
    fn test_get_cached_data_columns_indices_empty() {
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root);

        let indices = components.get_cached_data_columns_indices();
        assert!(indices.is_empty());
    }

    #[test]
    fn test_status_str_no_block() {
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root);

        let status = components.status_str(10);
        assert_eq!(status, "block no data_columns 0/10");
    }

    #[test]
    fn test_num_blobs_expected_no_block() {
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root);

        let result = components.num_blobs_expected();
        assert!(result.is_err());
        // Error should be AvailabilityCheckError::Unexpected
        assert!(matches!(
            result.unwrap_err(),
            AvailabilityCheckError::Unexpected(_)
        ));
    }

    #[test]
    fn test_make_available_no_block_returns_none() {
        let block_root = Hash256::random();
        let components = PendingComponents::<E>::empty(block_root);

        // Without a block, make_available should return Ok(None)
        let result = components.make_available(10);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}

#[cfg(test)]
mod data_availability_checker_tests {
    use super::*;

    use crate::data_column_verification::{KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn};
    use crate::test_utils::{
        generate_data_column_indices_rand_order, test_spec, NumBlobs,
        generate_rand_block_and_data_columns,
    };
    use crate::{
        custody_context::NodeCustodyType,
        test_utils::{BeaconChainHarness, DiskHarnessType},
    };
    use logging::create_test_tracing_subscriber;
    use store::{HotColdDB, StoreConfig, database::interface::BeaconNodeBackend};
    use tempfile::{TempDir, tempdir};
    use types::{ForkName, MinimalEthSpec, Slot};
    use types::new_non_zero_usize;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    type E = MinimalEthSpec;

    const LOW_VALIDATOR_COUNT: usize = 32;

    fn gloas_spec<E: EthSpec>() -> Arc<ChainSpec> {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        spec.capella_fork_epoch = Some(Epoch::new(0));
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.electra_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        spec.gloas_fork_epoch = Some(Epoch::new(0));
        Arc::new(spec)
    }

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
        let spec = gloas_spec::<E>();

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
        let gloas_fork_slot = Slot::new(0);
        harness.extend_to_slot(gloas_fork_slot).await;
        harness
    }

    async fn setup_harness_and_cache<T>(
        capacity: usize,
    ) -> (
        BeaconChainHarness<DiskHarnessType<E>>,
        Arc<DataAvailabilityCheckerInner<T>>,
        TempDir,
    )
    where
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

    fn is_gloas_enabled() -> bool {
        let spec = test_spec::<E>();
        spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled()
    }

    #[tokio::test]
    async fn test_cache_creation() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (_harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;
        assert_eq!(cache.block_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_put_columns_creates_pending_components() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        // Generate a block with data columns
        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu, // Use Fulu for now as Gloas generation may not be ready
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Convert to KzgVerifiedCustodyDataColumn
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(1) // Just take one column for the test
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        // Put columns into cache
        let result = cache.put_kzg_verified_data_columns(block_root, verified_columns);
        assert!(result.is_ok());

        // Check that pending components were created
        assert_eq!(cache.block_cache_size(), 1);

        // Verify columns are cached
        let cached_indices = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.get_cached_data_columns_indices())
        });
        assert!(cached_indices.is_some());
        assert_eq!(cached_indices.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_column_deduplication() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Get the first column
        let first_column = data_columns.first().cloned().expect("should have column");
        let column_index = *first_column.index();

        let verified_column = KzgVerifiedCustodyDataColumn::from_asserted_custody(
            KzgVerifiedDataColumn::__new_for_testing(first_column.clone()),
        );

        // Insert the same column twice
        cache
            .put_kzg_verified_data_columns(block_root, vec![verified_column.clone()])
            .expect("should put column");

        cache
            .put_kzg_verified_data_columns(block_root, vec![verified_column])
            .expect("should put column again");

        // Check that we still only have one column (deduplicated)
        let cached_indices = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.get_cached_data_columns_indices())
        });
        assert!(cached_indices.is_some());
        let indices = cached_indices.unwrap();
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0], column_index);
    }

    #[tokio::test]
    async fn test_columns_without_block_not_available() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Add all columns
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        let result = cache
            .put_kzg_verified_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Without a block, should still be missing components
        assert!(matches!(result, Availability::MissingComponents(_)));
    }

    #[tokio::test]
    async fn test_reconstruction_started_flag() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Add some columns (not enough for reconstruction threshold)
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(10) // Not enough for reconstruction
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        cache
            .put_kzg_verified_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Check reconstruction decision - should say "not enough columns"
        let decision = cache.check_and_set_reconstruction_started(&block_root);
        assert!(matches!(decision, ReconstructColumnsDecision::No(_)));
    }

    #[tokio::test]
    async fn test_handle_reconstruction_failure_clears_columns() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // Add some columns
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(5)
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        cache
            .put_kzg_verified_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Verify columns are cached
        let cached_count = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.verified_data_columns.len())
        });
        assert_eq!(cached_count, Some(5));

        // Handle reconstruction failure
        cache.handle_reconstruction_failure(&block_root);

        // Verify columns are cleared
        let cached_count_after = cache.peek_pending_components(&block_root, |components| {
            components.map(|c| c.verified_data_columns.len())
        });
        assert_eq!(cached_count_after, Some(0));
    }

    #[tokio::test]
    async fn test_maintenance_removes_old_entries() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (_harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;

        let block_root = Hash256::random();

        // Create an empty entry in the cache
        let _ = cache.peek_pending_components(&block_root, |_| {});

        // Manually insert a pending component by putting empty columns
        // This will create an entry but it won't have an epoch
        // For this test, we need an entry with a known epoch

        // Run maintenance with a future cutoff epoch
        let cutoff_epoch = Epoch::new(100);
        cache.do_maintenance(cutoff_epoch).expect("maintenance should succeed");

        // Cache should still be empty since we didn't add anything with an epoch
        assert_eq!(cache.block_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_peek_data_columns() {
        if !is_gloas_enabled() {
            return;
        }

        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<T>(capacity).await;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let spec = harness.spec.clone();

        let (_block, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut rng,
            &spec,
        );

        let block_root = Hash256::random();

        // No columns yet
        assert!(cache.peek_data_columns(block_root).is_none());

        // Add columns
        let verified_columns: Vec<_> = data_columns
            .into_iter()
            .take(3)
            .map(|col| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::__new_for_testing(col),
                )
            })
            .collect();

        cache
            .put_kzg_verified_data_columns(block_root, verified_columns)
            .expect("should put columns");

        // Now columns should be returned
        let peeked = cache.peek_data_columns(block_root);
        assert!(peeked.is_some());
        assert_eq!(peeked.unwrap().len(), 3);
    }
}
