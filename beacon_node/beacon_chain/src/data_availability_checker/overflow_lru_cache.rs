use super::state_lru_cache::{DietAvailabilityPendingExecutedBlock, StateLRUCache};
use crate::beacon_chain::BeaconStore;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableBlock, AvailableExecutedBlock,
};
use crate::data_availability_checker::{Availability, AvailabilityCheckError};
use crate::BeaconChainTypes;
use lru::LruCache;
use parking_lot::RwLock;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use std::num::NonZeroUsize;
use std::sync::Arc;
use types::blob_sidecar::BlobIdentifier;
use types::{BlobSidecar, ChainSpec, Epoch, EthSpec, Hash256, SignedBeaconBlock};

/// This represents the components of a partially available block
///
/// The blobs are all gossip and kzg verified.
/// The block has completed all verifications except the availability check.
#[derive(Encode, Decode, Clone)]
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub verified_blobs: FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock>,
    pub executed_block: Option<DietAvailabilityPendingExecutedBlock<E>>,
}

impl<E: EthSpec> PendingComponents<E> {
    /// Returns an immutable reference to the cached block.
    pub fn get_cached_block(&self) -> &Option<DietAvailabilityPendingExecutedBlock<E>> {
        &self.executed_block
    }

    /// Returns an immutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs(
        &self,
    ) -> &FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock> {
        &self.verified_blobs
    }

    /// Returns a mutable reference to the cached block.
    pub fn get_cached_block_mut(&mut self) -> &mut Option<DietAvailabilityPendingExecutedBlock<E>> {
        &mut self.executed_block
    }

    /// Returns a mutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs_mut(
        &mut self,
    ) -> &mut FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock> {
        &mut self.verified_blobs
    }

    /// Checks if a blob exists at the given index in the cache.
    ///
    /// Returns:
    /// - `true` if a blob exists at the given index.
    /// - `false` otherwise.
    pub fn blob_exists(&self, blob_index: usize) -> bool {
        self.get_cached_blobs()
            .get(blob_index)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    /// Returns the number of blobs that are expected to be present. Returns `None` if we don't have a
    /// block.
    ///
    /// This corresponds to the number of commitments that are present in a block.
    pub fn num_expected_blobs(&self) -> Option<usize> {
        self.get_cached_block()
            .as_ref()
            .map(|b| b.get_commitments().len())
    }

    /// Returns the number of blobs that have been received and are stored in the cache.
    pub fn num_received_blobs(&self) -> usize {
        self.get_cached_blobs().iter().flatten().count()
    }

    /// Inserts a block into the cache.
    pub fn insert_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        *self.get_cached_block_mut() = Some(block)
    }

    /// Inserts a blob at a specific index in the cache.
    ///
    /// Existing blob at the index will be replaced.
    pub fn insert_blob_at_index(&mut self, blob_index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(b) = self.get_cached_blobs_mut().get_mut(blob_index) {
            *b = Some(blob);
        }
    }

    /// Merges a given set of blobs into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists.
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_blobs(
        &mut self,
        blobs: FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock>,
    ) {
        for (index, blob) in blobs.iter().cloned().enumerate() {
            let Some(blob) = blob else { continue };
            self.merge_single_blob(index, blob);
        }
    }

    /// Merges a single blob into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists, or
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_single_blob(&mut self, index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(cached_block) = self.get_cached_block() {
            let block_commitment_opt = cached_block.get_commitments().get(index).copied();
            if let Some(block_commitment) = block_commitment_opt {
                if block_commitment == *blob.get_commitment() {
                    self.insert_blob_at_index(index, blob)
                }
            }
        } else if !self.blob_exists(index) {
            self.insert_blob_at_index(index, blob)
        }
    }

    /// Inserts a new block and revalidates the existing blobs against it.
    ///
    /// Blobs that don't match the new block's commitments are evicted.
    pub fn merge_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        self.insert_block(block);
        let reinsert = std::mem::take(self.get_cached_blobs_mut());
        self.merge_blobs(reinsert);
    }

    /// Checks if the block and all of its expected blobs are available in the cache.
    ///
    /// Returns `true` if both the block exists and the number of received blobs matches the number
    /// of expected blobs.
    pub fn is_available(&self) -> bool {
        if let Some(num_expected_blobs) = self.num_expected_blobs() {
            num_expected_blobs == self.num_received_blobs()
        } else {
            false
        }
    }

    /// Returns an empty `PendingComponents` object with the given block root.
    pub fn empty(block_root: Hash256) -> Self {
        Self {
            block_root,
            verified_blobs: FixedVector::default(),
            executed_block: None,
        }
    }

    /// Verifies an `SignedBeaconBlock` against a set of KZG verified blobs.
    /// This does not check whether a block *should* have blobs, these checks should have been
    /// completed when producing the `AvailabilityPendingBlock`.
    ///
    /// WARNING: This function can potentially take a lot of time if the state needs to be
    /// reconstructed from disk. Ensure you are not holding any write locks while calling this.
    pub fn make_available<R>(self, recover: R) -> Result<Availability<E>, AvailabilityCheckError>
    where
        R: FnOnce(
            DietAvailabilityPendingExecutedBlock<E>,
        ) -> Result<AvailabilityPendingExecutedBlock<E>, AvailabilityCheckError>,
    {
        let Self {
            block_root,
            verified_blobs,
            executed_block,
        } = self;

        let blobs_available_timestamp = verified_blobs
            .iter()
            .flatten()
            .map(|blob| blob.seen_timestamp())
            .max();

        let Some(diet_executed_block) = executed_block else {
            return Err(AvailabilityCheckError::Unexpected);
        };
        let num_blobs_expected = diet_executed_block.num_blobs_expected();
        let Some(verified_blobs) = verified_blobs
            .into_iter()
            .cloned()
            .map(|b| b.map(|b| b.to_blob()))
            .take(num_blobs_expected)
            .collect::<Option<Vec<_>>>()
        else {
            return Err(AvailabilityCheckError::Unexpected);
        };
        let verified_blobs = VariableList::new(verified_blobs)?;

        let executed_block = recover(diet_executed_block)?;

        let AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        } = executed_block;

        let available_block = AvailableBlock {
            block_root,
            block,
            blobs: Some(verified_blobs),
            blobs_available_timestamp,
        };
        Ok(Availability::Available(Box::new(
            AvailableExecutedBlock::new(available_block, import_data, payload_verification_outcome),
        )))
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
}

impl<T: BeaconChainTypes> DataAvailabilityCheckerInner<T> {
    pub fn new(
        capacity: NonZeroUsize,
        beacon_store: BeaconStore<T>,
        spec: ChainSpec,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            critical: RwLock::new(LruCache::new(capacity)),
            state_cache: StateLRUCache::new(beacon_store, spec),
        })
    }

    /// Returns true if the block root is known, without altering the LRU ordering
    pub fn get_execution_valid_block(
        &self,
        block_root: &Hash256,
    ) -> Option<Arc<SignedBeaconBlock<T::EthSpec>>> {
        self.critical
            .read()
            .peek(block_root)
            .and_then(|pending_components| {
                pending_components
                    .executed_block
                    .as_ref()
                    .map(|block| block.block_cloned())
            })
    }

    /// Fetch a blob from the cache without affecting the LRU ordering
    pub fn peek_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        if let Some(pending_components) = self.critical.read().peek(&blob_id.block_root) {
            Ok(pending_components
                .verified_blobs
                .get(blob_id.index as usize)
                .ok_or(AvailabilityCheckError::BlobIndexInvalid(blob_id.index))?
                .as_ref()
                .map(|blob| blob.clone_blob()))
        } else {
            Ok(None)
        }
    }

    pub fn peek_pending_components<R, F: FnOnce(Option<&PendingComponents<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        f(self.critical.read().peek(block_root))
    }

    pub fn put_kzg_verified_blobs<I: IntoIterator<Item = KzgVerifiedBlob<T::EthSpec>>>(
        &self,
        block_root: Hash256,
        kzg_verified_blobs: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut fixed_blobs = FixedVector::default();

        for blob in kzg_verified_blobs {
            if let Some(blob_opt) = fixed_blobs.get_mut(blob.blob_index() as usize) {
                *blob_opt = Some(blob);
            }
        }

        let mut write_lock = self.critical.write();

        // Grab existing entry or create a new entry.
        let mut pending_components = write_lock
            .pop_entry(&block_root)
            .map(|(_, v)| v)
            .unwrap_or_else(|| PendingComponents::empty(block_root));

        // Merge in the blobs.
        pending_components.merge_blobs(fixed_blobs);

        if pending_components.is_available() {
            write_lock.put(block_root, pending_components.clone());
            // No need to hold the write lock anymore
            drop(write_lock);
            pending_components.make_available(|diet_block| {
                self.state_cache.recover_pending_executed_block(diet_block)
            })
        } else {
            write_lock.put(block_root, pending_components);
            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// Check if we have all the blobs for a block. If we do, return the Availability variant that
    /// triggers import of the block.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut write_lock = self.critical.write();
        let block_root = executed_block.import_data.block_root;

        // register the block to get the diet block
        let diet_executed_block = self
            .state_cache
            .register_pending_executed_block(executed_block);

        // Grab existing entry or create a new entry.
        let mut pending_components = write_lock
            .pop_entry(&block_root)
            .map(|(_, v)| v)
            .unwrap_or_else(|| PendingComponents::empty(block_root));

        // Merge in the block.
        pending_components.merge_block(diet_executed_block);

        // Check if we have all components and entire set is consistent.
        if pending_components.is_available() {
            write_lock.put(block_root, pending_components.clone());
            // No need to hold the write lock anymore
            drop(write_lock);
            pending_components.make_available(|diet_block| {
                self.state_cache.recover_pending_executed_block(diet_block)
            })
        } else {
            write_lock.put(block_root, pending_components);
            Ok(Availability::MissingComponents(block_root))
        }
    }

    pub fn remove_pending_components(&self, block_root: Hash256) {
        self.critical.write().pop_entry(&block_root);
    }

    /// maintain the cache
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // clean up any lingering states in the state cache
        self.state_cache.do_maintenance(cutoff_epoch);
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
    pub fn block_cache_size(&self) -> usize {
        self.critical.read().len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        blob_verification::GossipVerifiedBlob,
        block_verification::PayloadVerificationOutcome,
        block_verification_types::{AsBlock, BlockImportData},
        data_availability_checker::STATE_LRU_CAPACITY,
        eth1_finalization_cache::Eth1FinalizationData,
        test_utils::{BaseHarnessType, BeaconChainHarness, DiskHarnessType},
    };
    use fork_choice::PayloadVerificationStatus;
    use logging::test_logger;
    use slog::{info, Logger};
    use state_processing::ConsensusContext;
    use std::collections::VecDeque;
    use store::{HotColdDB, ItemStore, LevelDB, StoreConfig};
    use tempfile::{tempdir, TempDir};
    use types::non_zero_usize::new_non_zero_usize;
    use types::{ExecPayload, MinimalEthSpec};

    const LOW_VALIDATOR_COUNT: usize = 32;

    fn get_store_with_spec<E: EthSpec>(
        db_path: &TempDir,
        spec: ChainSpec,
        log: Logger,
    ) -> Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>> {
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
            log,
        )
        .expect("disk store should initialize")
    }

    // get a beacon chain harness advanced to just before deneb fork
    async fn get_deneb_chain<E: EthSpec>(
        log: Logger,
        db_path: &TempDir,
    ) -> BeaconChainHarness<DiskHarnessType<E>> {
        let altair_fork_epoch = Epoch::new(1);
        let bellatrix_fork_epoch = Epoch::new(2);
        let bellatrix_fork_slot = bellatrix_fork_epoch.start_slot(E::slots_per_epoch());
        let capella_fork_epoch = Epoch::new(3);
        let deneb_fork_epoch = Epoch::new(4);
        let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(altair_fork_epoch);
        spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
        spec.capella_fork_epoch = Some(capella_fork_epoch);
        spec.deneb_fork_epoch = Some(deneb_fork_epoch);

        let chain_store = get_store_with_spec::<E>(db_path, spec.clone(), log.clone());
        let validators_keypairs =
            types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .logger(log.clone())
            .keypairs(validators_keypairs)
            .fresh_disk_store(chain_store)
            .mock_execution_layer()
            .build();

        // go to bellatrix slot
        harness.extend_to_slot(bellatrix_fork_slot).await;
        let bellatrix_head = &harness.chain.head_snapshot().beacon_block;
        assert!(bellatrix_head.as_bellatrix().is_ok());
        assert_eq!(bellatrix_head.slot(), bellatrix_fork_slot);
        assert!(
            bellatrix_head
                .message()
                .body()
                .execution_payload()
                .unwrap()
                .is_default_with_empty_roots(),
            "Bellatrix head is default payload"
        );
        // Trigger the terminal PoW block.
        harness
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
        // go right before deneb slot
        harness.extend_to_slot(deneb_fork_slot - 1).await;

        harness
    }

    async fn availability_pending_block<E, Hot, Cold>(
        harness: &BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>,
    ) -> (
        AvailabilityPendingExecutedBlock<E>,
        Vec<GossipVerifiedBlob<BaseHarnessType<E, Hot, Cold>>>,
    )
    where
        E: EthSpec,
        Hot: ItemStore<E>,
        Cold: ItemStore<E>,
    {
        let chain = &harness.chain;
        let log = chain.log.clone();
        let head = chain.head_snapshot();
        let parent_state = head.beacon_state.clone();

        let target_slot = chain.slot().expect("should get slot") + 1;
        let parent_root = head.beacon_block_root;
        let parent_block = chain
            .get_blinded_block(&parent_root)
            .expect("should get block")
            .expect("should have block");

        let parent_eth1_finalization_data = Eth1FinalizationData {
            eth1_data: parent_block.message().body().eth1_data().clone(),
            eth1_deposit_index: 0,
        };

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
        info!(log, "printing kzg commitments");
        for comm in Vec::from(
            block
                .message()
                .body()
                .blob_kzg_commitments()
                .expect("should be deneb fork")
                .clone(),
        ) {
            info!(log, "kzg commitment"; "commitment" => ?comm);
        }
        info!(log, "done printing kzg commitments");

        let gossip_verified_blobs = if let Some((kzg_proofs, blobs)) = maybe_blobs {
            let sidecars = BlobSidecar::build_sidecars(blobs, &block, kzg_proofs).unwrap();
            Vec::from(sidecars)
                .into_iter()
                .map(|sidecar| {
                    let subnet = sidecar.index;
                    GossipVerifiedBlob::new(sidecar, subnet, &harness.chain)
                        .expect("should validate blob")
                })
                .collect()
        } else {
            vec![]
        };

        let slot = block.slot();
        let consensus_context = ConsensusContext::<E>::new(slot);
        let import_data: BlockImportData<E> = BlockImportData {
            block_root,
            state,
            parent_block,
            parent_eth1_finalization_data,
            confirmed_state_roots: vec![],
            consensus_context,
        };

        let payload_verification_outcome = PayloadVerificationOutcome {
            payload_verification_status: PayloadVerificationStatus::Verified,
            is_valid_merge_transition_block: false,
        };

        let availability_pending_block = AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        };

        (availability_pending_block, gossip_verified_blobs)
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
        T: BeaconChainTypes<HotStore = LevelDB<E>, ColdStore = LevelDB<E>, EthSpec = E>,
    {
        let log = test_logger();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness = get_deneb_chain(log.clone(), &chain_db_path).await;
        let spec = harness.spec.clone();
        let test_store = harness.chain.store.clone();
        let capacity_non_zero = new_non_zero_usize(capacity);
        let cache = Arc::new(
            DataAvailabilityCheckerInner::<T>::new(capacity_non_zero, test_store, spec.clone())
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

        let (pending_block, blobs) = availability_pending_block(&harness).await;
        let root = pending_block.import_data.block_root;

        let blobs_expected = pending_block.num_blobs_expected();
        assert_eq!(
            blobs.len(),
            blobs_expected,
            "should have expected number of blobs"
        );
        assert!(cache.critical.read().is_empty(), "cache should be empty");
        let availability = cache
            .put_pending_executed_block(pending_block)
            .expect("should put block");
        if blobs_expected == 0 {
            assert!(
                matches!(availability, Availability::Available(_)),
                "block doesn't have blobs, should be available"
            );
            assert_eq!(
                cache.critical.read().len(),
                1,
                "cache should still have block as it hasn't been imported yet"
            );
            // remove the blob to simulate successful import
            cache.remove_pending_components(root);
            assert_eq!(
                cache.critical.read().len(),
                0,
                "cache should be empty now that block has been imported"
            );
        } else {
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending blobs"
            );
            assert_eq!(
                cache.critical.read().len(),
                1,
                "cache should have one block"
            );
            assert!(
                cache.critical.read().peek(&root).is_some(),
                "newly inserted block should exist in memory"
            );
        }

        let mut kzg_verified_blobs = Vec::new();
        for (blob_index, gossip_blob) in blobs.into_iter().enumerate() {
            kzg_verified_blobs.push(gossip_blob.into_inner());
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.clone())
                .expect("should put blob");
            if blob_index == blobs_expected - 1 {
                assert!(matches!(availability, Availability::Available(_)));
            } else {
                assert!(matches!(availability, Availability::MissingComponents(_)));
                assert_eq!(cache.critical.read().len(), 1);
            }
        }
        assert!(
            cache.critical.read().is_empty(),
            "cache should be empty now that all components available"
        );

        let (pending_block, blobs) = availability_pending_block(&harness).await;
        let blobs_expected = pending_block.num_blobs_expected();
        assert_eq!(
            blobs.len(),
            blobs_expected,
            "should have expected number of blobs"
        );
        let root = pending_block.import_data.block_root;
        let mut kzg_verified_blobs = vec![];
        for gossip_blob in blobs {
            kzg_verified_blobs.push(gossip_blob.into_inner());
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.clone())
                .expect("should put blob");
            assert_eq!(
                availability,
                Availability::MissingComponents(root),
                "should be pending block"
            );
            assert_eq!(cache.critical.read().len(), 1);
        }
        let availability = cache
            .put_pending_executed_block(pending_block)
            .expect("should put block");
        assert!(
            matches!(availability, Availability::Available(_)),
            "block should be available: {:?}",
            availability
        );
        assert!(
            cache.critical.read().len() == 1,
            "cache should still have available block until import"
        );
        // remove the blob to simulate successful import
        cache.remove_pending_components(root);
        assert!(
            cache.critical.read().is_empty(),
            "cache should be empty now that all components available"
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
            let (pending_block, _) = availability_pending_block(&harness).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let state_root = pending_block.import_data.state.canonical_root();
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
                .put_pending_executed_block(pending_block)
                .expect("should put block");

            // grab the diet block from the cache for later testing
            let diet_block = cache
                .critical
                .read()
                .peek(&block_root)
                .map(|pending_components| {
                    pending_components
                        .executed_block
                        .clone()
                        .expect("should exist")
                })
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
                    .recover_pending_executed_block(diet_block)
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
            .recover_pending_executed_block(diet_block)
            .expect("should reconstruct pending block");
        // assert the recovered state is the same as the original
        assert_eq!(
            Some(&recovered_pending_block.import_data.state),
            states.last(),
            "recovered state should be the same as the original"
        );
        // the state should no longer be in the cache
        assert!(
            state_cache
                .read()
                .peek(&last_block.as_block().state_root())
                .is_none(),
            "last block state should no longer be in cache"
        );
    }
}

#[cfg(test)]
mod pending_components_tests {
    use super::*;
    use crate::block_verification_types::BlockImportData;
    use crate::eth1_finalization_cache::Eth1FinalizationData;
    use crate::test_utils::{generate_rand_block_and_blobs, NumBlobs};
    use crate::PayloadVerificationOutcome;
    use fork_choice::PayloadVerificationStatus;
    use kzg::KzgCommitment;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use state_processing::ConsensusContext;
    use types::test_utils::TestRandom;
    use types::{BeaconState, ForkName, MainnetEthSpec, SignedBeaconBlock, Slot};

    type E = MainnetEthSpec;

    type Setup<E> = (
        SignedBeaconBlock<E>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn pre_setup() -> Setup<E> {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
        let (block, blobs_vec) =
            generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Random, &mut rng);
        let mut blobs: FixedVector<_, <E as EthSpec>::MaxBlobsPerBlock> = FixedVector::default();

        for blob in blobs_vec {
            if let Some(b) = blobs.get_mut(blob.index as usize) {
                *b = Some(Arc::new(blob));
            }
        }

        let mut invalid_blobs: FixedVector<
            Option<Arc<BlobSidecar<E>>>,
            <E as EthSpec>::MaxBlobsPerBlock,
        > = FixedVector::default();
        for (index, blob) in blobs.iter().enumerate() {
            if let Some(invalid_blob) = blob {
                let mut blob_copy = invalid_blob.as_ref().clone();
                blob_copy.kzg_commitment = KzgCommitment::random_for_test(&mut rng);
                *invalid_blobs.get_mut(index).unwrap() = Some(Arc::new(blob_copy));
            }
        }

        (block, blobs, invalid_blobs)
    }

    type PendingComponentsSetup<E> = (
        DietAvailabilityPendingExecutedBlock<E>,
        FixedVector<Option<KzgVerifiedBlob<E>>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<KzgVerifiedBlob<E>>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn setup_pending_components(
        block: SignedBeaconBlock<E>,
        valid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        invalid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    ) -> PendingComponentsSetup<E> {
        let blobs = FixedVector::from(
            valid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let invalid_blobs = FixedVector::from(
            invalid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let dummy_parent = block.clone_as_blinded();
        let block = AvailabilityPendingExecutedBlock {
            block: Arc::new(block),
            import_data: BlockImportData {
                block_root: Default::default(),
                state: BeaconState::new(0, Default::default(), &ChainSpec::minimal()),
                parent_block: dummy_parent,
                parent_eth1_finalization_data: Eth1FinalizationData {
                    eth1_data: Default::default(),
                    eth1_deposit_index: 0,
                },
                confirmed_state_roots: vec![],
                consensus_context: ConsensusContext::new(Slot::new(0)),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        };
        (block.into(), blobs, invalid_blobs)
    }

    pub fn assert_cache_consistent(cache: PendingComponents<E>) {
        if let Some(cached_block) = cache.get_cached_block() {
            let cached_block_commitments = cached_block.get_commitments();
            for index in 0..E::max_blobs_per_block() {
                let block_commitment = cached_block_commitments.get(index).copied();
                let blob_commitment_opt = cache.get_cached_blobs().get(index).unwrap();
                let blob_commitment = blob_commitment_opt.as_ref().map(|b| *b.get_commitment());
                assert_eq!(block_commitment, blob_commitment);
            }
        } else {
            panic!("No cached block")
        }
    }

    pub fn assert_empty_blob_cache(cache: PendingComponents<E>) {
        for blob in cache.get_cached_blobs().iter() {
            assert!(blob.is_none());
        }
    }

    #[test]
    fn valid_block_invalid_blobs_valid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn invalid_blobs_block_valid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn invalid_blobs_valid_blobs_block() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);

        assert_empty_blob_cache(cache);
    }

    #[test]
    fn block_valid_blobs_invalid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn valid_blobs_block_invalid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn valid_blobs_invalid_blobs_block() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);

        assert_cache_consistent(cache);
    }
}
