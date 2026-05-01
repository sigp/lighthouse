//! This module builds out the data availability cache for Gloas. When a beacon block is received
//! over gossip/p2p we insert its payload into this cache, keyed by block root. As soon as the bid
//! is received we can begin using it to verify data columns.
//!
//! When a payload envelope is received over gossip/p2p we first insert it as a pre-executed envelope. A separate
//! thread eventually executes the payload envelope against the EL. Assuming the payload is executed successfully
//! the envelope is updated in the cache from `PreExecuted` -> `Executed`. Once all required custody columns
//! have been kzg verified and the envelope has been executed we can import the envelope into fork choice and store it to disk.
//!
//! Note that the block must have arrived before the envelope for the envelope to pass upstream verification checks and reach this cache.
//! However data columns can potentially arrive before the block.

use crate::data_availability_checker::{AvailabilityCheckError, MissingCellsError};
use crate::payload_envelope_verification::{
    AvailabilityPendingExecutedEnvelope, AvailableExecutedEnvelope,
};
use crate::{BeaconChain, BeaconChainTypes, CustodyContext, metrics};
use kzg::Kzg;
use lru::LruCache;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tracing::{Span, debug, error, instrument, trace};
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Hash256,
    PartialDataColumnSidecarRef,
};

mod pending_column;
mod pending_components;

use crate::data_column_verification::{
    GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn,
};
use crate::metrics::{
    KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS, KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES,
};
use crate::observed_data_sidecars::ObservationStrategy;
pub use pending_components::signed_payload_bid_from_block;
use pending_components::{PendingComponents, ReconstructColumnsDecision};
use types::SignedExecutionPayloadBid;
use types::new_non_zero_usize;

/// The LRU Cache stores `PendingComponents`, which store the block root, the execution payload bid, and its associated column data.
/// The execution payload bid stores the kzg commitments which we use to verify against incoming column data.
/// Setting this to 32 keeps memory usage reasonable.
///
/// `PendingComponents` are now never removed from the cache manually and are only removed via LRU
/// eviction to prevent race conditions (#7961), so we expect this cache to be full all the time.
const OVERFLOW_LRU_CAPACITY_NON_ZERO: NonZeroUsize = new_non_zero_usize(32);

/// This type is returned after adding a bid / column to the `DataAvailabilityChecker`.
///
/// Indicates if the payloads data is fully `Available` or if we need more columns.
pub enum Availability<E: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedEnvelope<E>>),
}

impl<E: EthSpec> Debug for Availability<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingComponents(block_root) => {
                write!(f, "MissingComponents({})", block_root)
            }
            Self::Available(envelope) => {
                write!(f, "Available({:?})", envelope.block_root)
            }
        }
    }
}

pub type AvailabilityAndReconstructedColumns<E> = (Availability<E>, DataColumnSidecarList<E>);

#[derive(Debug)]
pub enum DataColumnReconstructionResult<E: EthSpec> {
    Success(AvailabilityAndReconstructedColumns<E>),
    NotStarted(&'static str),
    RecoveredColumnsNotImported(&'static str),
}

/// Cache to hold data columns for payloads pending data availability.
///
/// In Gloas, beacon blocks can be immediately imported into fork choice. The execution payload
/// bid contains the payloads kzg commitments. This cache tracks data columns for payloads until all
/// required columns are received.
///
/// Usually data becomes available on its slot within a second of receiving its first component
/// over gossip. However, data may never become available if a malicious proposer does not
/// publish its data, or there are network issues. Components are only removed via LRU eviction.
pub struct PendingPayloadCache<T: BeaconChainTypes> {
    /// Contains all the data we keep in memory, protected by an RwLock
    availability_cache: RwLock<LruCache<Hash256, PendingComponents<T::EthSpec>>>,
    kzg: Arc<Kzg>,
    custody_context: Arc<CustodyContext<T::EthSpec>>,
    spec: Arc<ChainSpec>,
}

impl<T: BeaconChainTypes> PendingPayloadCache<T> {
    pub fn new(
        kzg: Arc<Kzg>,
        custody_context: Arc<CustodyContext<T::EthSpec>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            availability_cache: RwLock::new(LruCache::new(OVERFLOW_LRU_CAPACITY_NON_ZERO)),
            kzg,
            custody_context,
            spec,
        })
    }

    pub fn custody_context(&self) -> &Arc<CustodyContext<T::EthSpec>> {
        &self.custody_context
    }

    /// Returns all cached data columns for the given block root, if any.
    #[instrument(skip_all, level = "trace")]
    pub fn get_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.peek_pending_components(&block_root, |components| {
            components.map(|c| c.get_cached_data_columns())
        })
    }

    /// Returns the indices of cached data columns for the given block root.
    #[instrument(skip_all, level = "trace")]
    pub fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<ColumnIndex>> {
        self.peek_pending_components(block_root, |components| {
            components.map(|components| components.get_cached_data_columns_indices())
        })
    }

    /// Return the cached Gloas payload bid for `block_root`, if present.
    pub fn get_bid(
        &self,
        block_root: &Hash256,
    ) -> Option<Arc<SignedExecutionPayloadBid<T::EthSpec>>> {
        self.peek_pending_components(block_root, |components| {
            components.map(|components| components.bid.clone())
        })
    }

    /// Filter out cells that are already cached for the given column sidecar.
    /// Returns the cells that still need KZG verification, or `None` if all cells are cached.
    #[instrument(skip_all, level = "trace")]
    pub fn missing_cells_for_column_sidecar<'a>(
        &'_ self,
        data_column: &'a DataColumnSidecar<T::EthSpec>,
    ) -> Result<Option<PartialDataColumnSidecarRef<'a, T::EthSpec>>, MissingCellsError> {
        let block_root = data_column.block_root();
        let column_index = *data_column.index();

        self.peek_pending_components(&block_root, |components| {
            let Some(cached) = components.and_then(|c| c.verified_data_columns.get(&column_index))
            else {
                return data_column.try_filter_to_partial_ref(|_, _, _| Ok(true));
            };

            data_column.try_filter_to_partial_ref(|cell_idx, cell, proof| {
                match cached.cell_matches(cell_idx, cell, proof) {
                    None => Ok(true),
                    Some(true) => Ok(false),
                    Some(false) => Err(MissingCellsError::MismatchesCachedColumn),
                }
            })
        })
    }

    /// Insert an executed payload envelope into the cache and performs an availability check
    pub fn put_executed_payload_envelope(
        &self,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        executed_envelope: AvailabilityPendingExecutedEnvelope<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = executed_envelope.envelope.epoch();
        let beacon_block_root = executed_envelope.envelope.beacon_block_root();
        let pending_components =
            self.get_pending_components(beacon_block_root, bid, |pending_components| {
                pending_components.insert_executed_payload_envelope(executed_envelope);
            })?;

        let num_expected_columns = self
            .custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec);

        pending_components.span.in_scope(|| {
            debug!(
                component = "executed envelope",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability(beacon_block_root, pending_components, num_expected_columns)
    }

    /// Inserts a bid into the pending payload cache.
    pub fn insert_bid(&self, block_root: Hash256, bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>) {
        let mut write_lock = self.availability_cache.write();
        write_lock.get_or_insert_mut(block_root, || PendingComponents::new(block_root, bid));
    }

    /// Perform KZG verification on RPC custody columns and insert them into the cache.
    /// After insertion check if the envelope becomes available.
    #[instrument(skip_all, level = "trace")]
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let kzg_verified_columns = KzgVerifiedDataColumn::from_batch_with_scoring_and_commitments(
            custody_columns,
            bid.message.blob_kzg_commitments.as_ref(),
            &self.kzg,
        )
        .map_err(AvailabilityCheckError::InvalidColumn)?;

        let epoch = bid.message.slot.epoch(T::EthSpec::slots_per_epoch());
        let sampling_columns = self
            .custody_context
            .sampling_columns_for_epoch(epoch, &self.spec);
        let verified_custody_columns = kzg_verified_columns
            .into_iter()
            .filter(|col| sampling_columns.contains(&col.index()))
            .map(KzgVerifiedCustodyDataColumn::from_asserted_custody)
            .collect::<Vec<_>>();

        self.put_kzg_verified_custody_data_columns(block_root, bid, &verified_custody_columns)
    }

    /// Perform KZG verification on gossip verified custody columns and insert them into the cache.
    /// After insertion check if the envelope becomes available
    #[instrument(skip_all, level = "trace")]
    pub fn put_gossip_verified_data_columns<O: ObservationStrategy>(
        &self,
        block_root: Hash256,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        data_columns: Vec<GossipVerifiedDataColumn<T, O>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = bid.message.slot.epoch(T::EthSpec::slots_per_epoch());
        let sampling_columns = self
            .custody_context
            .sampling_columns_for_epoch(epoch, &self.spec);
        let custody_columns = data_columns
            .into_iter()
            .filter(|col| sampling_columns.contains(&col.index()))
            .map(|c| KzgVerifiedCustodyDataColumn::from_asserted_custody(c.into_inner()))
            .collect::<Vec<_>>();

        self.put_kzg_verified_custody_data_columns(block_root, bid, &custody_columns)
    }

    /// Insert KZG verified columns into the cache.
    /// After insertion check if the envelope becomes available.
    pub fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        kzg_verified_data_columns: &[KzgVerifiedCustodyDataColumn<T::EthSpec>],
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let pending_components =
            self.get_pending_components(block_root, bid.clone(), |pending_components| {
                pending_components.merge_data_columns(kzg_verified_data_columns)
            })?;

        let epoch = bid.message.slot.epoch(T::EthSpec::slots_per_epoch());

        let num_expected_columns = self
            .custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec);

        pending_components.span.in_scope(|| {
            debug!(
                component = "data_columns",
                status = pending_components.status_str(num_expected_columns),
                "Component added to data availability checker"
            );
        });

        self.check_availability(block_root, pending_components, num_expected_columns)
    }

    #[instrument(skip_all, level = "debug")]
    pub fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    ) -> Result<DataColumnReconstructionResult<T::EthSpec>, AvailabilityCheckError> {
        let verified_data_columns = match self.check_and_set_reconstruction_started(block_root) {
            ReconstructColumnsDecision::Yes(verified_data_columns) => verified_data_columns,
            ReconstructColumnsDecision::No(reason) => {
                return Ok(DataColumnReconstructionResult::NotStarted(reason));
            }
        };
        let existing_column_indices = verified_data_columns
            .iter()
            .map(|data_column| *data_column.index())
            .collect::<Vec<_>>();

        metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_ATTEMPTS);
        let timer = metrics::start_timer(&metrics::DATA_AVAILABILITY_RECONSTRUCTION_TIME);

        let all_data_columns = KzgVerifiedCustodyDataColumn::reconstruct_columns(
            &self.kzg,
            verified_data_columns,
            &self.spec,
        )
        .map_err(|e| {
            error!(
                ?block_root,
                error = ?e,
                "Error reconstructing data columns"
            );
            self.handle_reconstruction_failure(block_root);
            metrics::inc_counter(&KZG_DATA_COLUMN_RECONSTRUCTION_FAILURES);
            AvailabilityCheckError::ReconstructColumnsError(e)
        })?;

        let Some(slot) = all_data_columns.first().map(|d| d.as_data_column().slot()) else {
            return Ok(DataColumnReconstructionResult::RecoveredColumnsNotImported(
                "No new columns to import and publish",
            ));
        };

        let columns_to_sample = self
            .custody_context()
            .sampling_columns_for_epoch(slot.epoch(T::EthSpec::slots_per_epoch()), &self.spec);

        let data_columns_to_import_and_publish = all_data_columns
            .into_iter()
            .filter(|d| {
                columns_to_sample.contains(&d.index())
                    && !existing_column_indices.contains(&d.index())
            })
            .collect::<Vec<_>>();

        metrics::stop_timer(timer);
        metrics::inc_counter_by(
            &metrics::DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS,
            data_columns_to_import_and_publish.len() as u64,
        );

        debug!(
            count = data_columns_to_import_and_publish.len(),
            ?block_root,
            %slot,
            "Reconstructed columns"
        );

        self.put_kzg_verified_custody_data_columns(
            *block_root,
            bid,
            &data_columns_to_import_and_publish,
        )
        .map(|availability| {
            DataColumnReconstructionResult::Success((
                availability,
                data_columns_to_import_and_publish
                    .into_iter()
                    .map(|d| d.clone_arc())
                    .collect::<Vec<_>>(),
            ))
        })
    }

    // ── Metrics ──

    /// Collects metrics from the data availability checker.
    pub fn metrics(&self) -> DataAvailabilityCheckerMetrics {
        DataAvailabilityCheckerMetrics {
            block_cache_size: self.block_cache_size(),
        }
    }

    /// Number of pending component entries in memory in the cache.
    pub fn block_cache_size(&self) -> usize {
        self.availability_cache.read().len()
    }

    // ── Internal helpers ──

    fn check_availability(
        &self,
        block_root: Hash256,
        pending_components: MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>,
        num_expected_columns: usize,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if let Some(available_envelope) = pending_components.make_available(num_expected_columns)? {
            // Explicitly drop read lock before acquiring write lock
            drop(pending_components);
            if let Some(components) = self.availability_cache.write().get_mut(&block_root) {
                // Clean up span now that data is available
                components.span = Span::none();
            }

            // We never remove the pending components manually to avoid race conditions.
            // Components are only removed via LRU eviction as finality advances.
            Ok(Availability::Available(Box::new(available_envelope)))
        } else {
            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// Gets or creates `PendingComponents` and applies the `update_fn` while holding the write lock.
    ///
    /// Once the update is complete, the write lock is downgraded and a read guard with a
    /// reference of the updated `PendingComponents` is returned.
    ///
    fn get_pending_components<F>(
        &self,
        block_root: Hash256,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        update_fn: F,
    ) -> Result<MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>, AvailabilityCheckError>
    where
        F: FnOnce(&mut PendingComponents<T::EthSpec>),
    {
        let mut write_lock = self.availability_cache.write();

        {
            let pending_components = write_lock
                .get_or_insert_mut(block_root, || PendingComponents::new(block_root, bid));
            update_fn(pending_components)
        }

        RwLockReadGuard::try_map(RwLockWriteGuard::downgrade(write_lock), |cache| {
            cache.peek(&block_root)
        })
        .map_err(|_| {
            AvailabilityCheckError::Unexpected("pending components should exist".to_string())
        })
    }

    fn peek_pending_components<R, F: FnOnce(Option<&PendingComponents<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        f(self.availability_cache.read().peek(block_root))
    }

    /// Check whether data column reconstruction should be attempted.
    /// TODO(gloas): rethink reconstruction for the cell model
    fn check_and_set_reconstruction_started(
        &self,
        block_root: &Hash256,
    ) -> ReconstructColumnsDecision<T::EthSpec> {
        let mut write_lock = self.availability_cache.write();
        let Some(pending_components) = write_lock.get_mut(block_root) else {
            return ReconstructColumnsDecision::No("block already imported");
        };

        let epoch = pending_components.bid.epoch();

        let total_column_count = T::EthSpec::number_of_columns();
        let sampling_column_count = self
            .custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec);

        if pending_components.reconstruction_started {
            return ReconstructColumnsDecision::No("already started");
        }
        let received_column_count = pending_components.num_completed_columns();
        if received_column_count >= sampling_column_count {
            return ReconstructColumnsDecision::No("all sampling columns received");
        }
        if received_column_count < total_column_count / 2 {
            return ReconstructColumnsDecision::No("not enough columns");
        }

        pending_components.reconstruction_started = true;
        ReconstructColumnsDecision::Yes(pending_components.get_cached_data_columns())
    }

    /// This could mean some invalid data columns made it through to the `DataAvailabilityChecker`.
    /// In this case, we remove all data columns in `PendingComponents`, reset reconstruction
    /// status so that we can attempt to retrieve columns from peers again.
    fn handle_reconstruction_failure(&self, block_root: &Hash256) {
        if let Some(pending_components_mut) = self.availability_cache.write().get_mut(block_root) {
            pending_components_mut.verified_data_columns = HashMap::new();
            pending_components_mut.reconstruction_started = false;
        }
    }

    /// Maintain the cache by removing entries older than the cutoff epoch.
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        let mut write_lock = self.availability_cache.write();
        let mut keys_to_remove = vec![];
        for (key, value) in write_lock.iter() {
            if value.bid.epoch() < cutoff_epoch {
                keys_to_remove.push(*key);
            }
        }
        for key in keys_to_remove {
            write_lock.pop(&key);
        }

        Ok(())
    }
}

/// Helper struct to group data availability checker metrics.
pub struct DataAvailabilityCheckerMetrics {
    pub block_cache_size: usize,
}

pub fn start_availability_cache_maintenance_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    if chain.spec.gloas_fork_epoch.is_some() {
        let da_checker = chain.pending_payload_cache.clone();
        executor.spawn(
            async move { availability_cache_maintenance_service(chain, da_checker).await },
            "availability_cache_service",
        );
    } else {
        trace!("Gloas fork not configured, not starting availability cache maintenance service");
    }
}

async fn availability_cache_maintenance_service<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    da_checker: Arc<PendingPayloadCache<T>>,
) {
    let epoch_duration = chain.slot_clock.slot_duration() * T::EthSpec::slots_per_epoch() as u32;
    loop {
        match chain
            .slot_clock
            .duration_to_next_epoch(T::EthSpec::slots_per_epoch())
        {
            Some(duration) => {
                // this service should run 3/4 of the way through the epoch
                let additional_delay = (epoch_duration * 3) / 4;
                tokio::time::sleep(duration + additional_delay).await;

                let Some(gloas_fork_epoch) = chain.spec.gloas_fork_epoch else {
                    // shutdown service if gloas fork epoch not set
                    break;
                };

                debug!("Availability cache maintenance service firing");
                let Some(current_epoch) = chain
                    .slot_clock
                    .now()
                    .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                else {
                    continue;
                };

                if current_epoch < gloas_fork_epoch {
                    // we are not in gloas yet
                    continue;
                }

                let finalized_epoch = chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .finalized_checkpoint()
                    .epoch;

                let Some(min_epochs_for_blobs) = chain
                    .spec
                    .min_epoch_data_availability_boundary(current_epoch)
                else {
                    // Shutdown service if deneb fork epoch not set.
                    break;
                };

                // any data belonging to an epoch before this should be pruned
                let cutoff_epoch = std::cmp::max(finalized_epoch + 1, min_epochs_for_blobs);

                if let Err(e) = da_checker.do_maintenance(cutoff_epoch) {
                    error!(error = ?e,"Failed to maintain availability cache");
                }
            }
            None => {
                error!("Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                tokio::time::sleep(chain.slot_clock.slot_duration()).await;
            }
        };
    }
}

#[cfg(test)]
mod data_availability_checker_tests {
    use super::*;

    use crate::block_verification::PayloadVerificationOutcome;
    use crate::test_utils::{
        NumBlobs, generate_data_column_indices_rand_order, generate_rand_block_and_data_columns,
    };
    use crate::{
        custody_context::NodeCustodyType,
        test_utils::{BeaconChainHarness, DiskHarnessType},
    };
    use fork_choice::PayloadVerificationStatus;
    use logging::create_test_tracing_subscriber;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use store::{HotColdDB, StoreConfig, database::interface::BeaconNodeBackend};
    use tempfile::{TempDir, tempdir};
    use types::{
        ExecutionPayloadEnvelope, ExecutionPayloadGloas, ExecutionRequests, ForkName,
        MinimalEthSpec, SignedExecutionPayloadEnvelope,
    };

    type E = MinimalEthSpec;
    type T = DiskHarnessType<E>;

    const LOW_VALIDATOR_COUNT: usize = 32;
    const RNG_SEED: u64 = 0xDEADBEEF;

    fn gloas_spec<E: EthSpec>() -> Arc<ChainSpec> {
        Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()))
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
        BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .keypairs(validators_keypairs)
            .fresh_disk_store(chain_store)
            .mock_execution_layer()
            .build()
    }

    async fn setup() -> (BeaconChainHarness<T>, Arc<PendingPayloadCache<T>>, TempDir) {
        create_test_tracing_subscriber();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness = get_gloas_chain::<E>(&chain_db_path).await;
        let spec = harness.spec.clone();
        let custody_context = Arc::new(CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        ));

        let cache = Arc::new(
            PendingPayloadCache::<T>::new(harness.chain.kzg.clone(), custody_context, spec.clone())
                .expect("should create cache"),
        );
        (harness, cache, chain_db_path)
    }

    fn make_test_signed_envelope(block_root: Hash256) -> Arc<SignedExecutionPayloadEnvelope<E>> {
        Arc::new(SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope {
                payload: ExecutionPayloadGloas::default(),
                execution_requests: ExecutionRequests::default(),
                builder_index: 0,
                beacon_block_root: block_root,
                parent_beacon_block_root: Hash256::random(),
            },
            signature: bls::Signature::infinity().expect("should create infinity sig"),
        })
    }

    fn make_test_executed_envelope(block_root: Hash256) -> AvailabilityPendingExecutedEnvelope<E> {
        AvailabilityPendingExecutedEnvelope {
            envelope: make_test_signed_envelope(block_root),
            block_root,
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
            },
        }
    }

    fn init_block(
        cache: &PendingPayloadCache<T>,
        spec: &ChainSpec,
        num_blobs: NumBlobs,
        seed: u64,
    ) -> (
        Arc<SignedExecutionPayloadBid<E>>,
        Hash256,
        DataColumnSidecarList<E>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (block, data_columns) =
            generate_rand_block_and_data_columns::<E>(ForkName::Gloas, num_blobs, &mut rng, spec);
        let block_root = block.canonical_root();
        let bid = signed_payload_bid_from_block(&block).expect("should get payload bid");
        cache.insert_bid(block_root, bid.clone());
        (bid, block_root, data_columns)
    }

    #[tokio::test]
    async fn caches_and_deduplicates_columns() {
        let (harness, cache, _path) = setup().await;
        let (bid, block_root, data_columns) =
            init_block(&cache, &harness.spec, NumBlobs::Number(1), RNG_SEED);
        let epoch = bid.message.slot.epoch(E::slots_per_epoch());
        let sampling_cols = cache
            .custody_context()
            .sampling_columns_for_epoch(epoch, &harness.spec);
        let column = data_columns
            .iter()
            .find(|c| sampling_cols.contains(c.index()))
            .cloned()
            .expect("should have a sampling column");
        let column_index = *column.index();

        for _ in 0..2 {
            cache
                .put_rpc_custody_columns(block_root, bid.clone(), vec![column.clone()])
                .expect("should put column");
        }

        assert_eq!(
            cache.cached_data_column_indexes(&block_root),
            Some(vec![column_index])
        );
        assert_eq!(
            cache.get_data_columns(block_root).map(|cols| cols.len()),
            Some(1)
        );
        assert_eq!(cache.block_cache_size(), 1);
    }

    #[tokio::test]
    async fn requires_columns_and_executed_envelope() {
        let (harness, cache, _path) = setup().await;
        let (bid, block_root, data_columns) =
            init_block(&cache, &harness.spec, NumBlobs::Number(1), RNG_SEED);

        let epoch = bid.message.slot.epoch(E::slots_per_epoch());
        let num_sampling_columns = cache
            .custody_context()
            .sampling_columns_for_epoch(epoch, &harness.spec)
            .len();

        let result = cache
            .put_rpc_custody_columns(block_root, bid.clone(), data_columns)
            .expect("should put columns");
        assert!(matches!(result, Availability::MissingComponents(_)));

        let result = cache
            .put_executed_payload_envelope(bid, make_test_executed_envelope(block_root))
            .expect("should put executed envelope");
        let Availability::Available(envelope) = result else {
            panic!("expected available envelope");
        };
        assert_eq!(envelope.block_root, block_root);
        assert_eq!(envelope.envelope.columns.len(), num_sampling_columns);
    }

    #[tokio::test]
    async fn zero_blob_envelope_is_available_without_columns() {
        let (harness, cache, _path) = setup().await;
        let (bid, block_root, _columns) =
            init_block(&cache, &harness.spec, NumBlobs::Number(0), RNG_SEED);

        let result = cache
            .put_executed_payload_envelope(bid, make_test_executed_envelope(block_root))
            .expect("should put executed envelope");
        let Availability::Available(envelope) = result else {
            panic!("zero-blob block should be available");
        };
        assert!(envelope.envelope.columns.is_empty());
    }

    #[tokio::test]
    async fn partial_columns_wait_for_missing_columns() {
        let (harness, cache, _path) = setup().await;
        let (bid, block_root, data_columns) =
            init_block(&cache, &harness.spec, NumBlobs::Number(1), RNG_SEED);

        cache
            .put_executed_payload_envelope(bid.clone(), make_test_executed_envelope(block_root))
            .expect("should put executed envelope");

        let columns = data_columns.into_iter().take(1).collect();
        let result = cache
            .put_rpc_custody_columns(block_root, bid, columns)
            .expect("should put columns");
        assert!(matches!(result, Availability::MissingComponents(_)));
    }

    #[tokio::test]
    async fn reconstruction_failure_clears_columns() {
        let (harness, cache, _path) = setup().await;
        let (bid, block_root, data_columns) =
            init_block(&cache, &harness.spec, NumBlobs::Number(1), RNG_SEED);

        let epoch = bid.message.slot.epoch(E::slots_per_epoch());
        let sampling_cols = cache
            .custody_context()
            .sampling_columns_for_epoch(epoch, &harness.spec);
        let columns: Vec<_> = data_columns
            .into_iter()
            .filter(|c| sampling_cols.contains(c.index()))
            .take(5)
            .collect();
        let num_columns = columns.len();

        cache
            .put_rpc_custody_columns(block_root, bid, columns)
            .expect("should put columns");
        assert_eq!(
            cache
                .cached_data_column_indexes(&block_root)
                .map(|indices| indices.len()),
            Some(num_columns)
        );

        cache.handle_reconstruction_failure(&block_root);
        assert_eq!(cache.cached_data_column_indexes(&block_root), Some(vec![]));
    }

    #[tokio::test]
    async fn lru_eviction_keeps_cache_bounded() {
        let (harness, cache, _path) = setup().await;
        let mut roots = Vec::new();

        for i in 0..33 {
            let (bid, block_root, data_columns) =
                init_block(&cache, &harness.spec, NumBlobs::Number(1), RNG_SEED + i);
            let column = data_columns.first().cloned().expect("should have column");
            roots.push(block_root);
            cache
                .put_rpc_custody_columns(block_root, bid, vec![column])
                .expect("should put columns");
        }

        assert_eq!(cache.block_cache_size(), 32);
        assert!(cache.get_data_columns(roots[0]).is_none());
        assert!(cache.get_data_columns(*roots.last().unwrap()).is_some());
    }

    #[tokio::test]
    async fn maintenance_prunes_old_entries() {
        let (harness, cache, _path) = setup().await;
        let (bid, block_root, data_columns) =
            init_block(&cache, &harness.spec, NumBlobs::Number(1), RNG_SEED);
        let block_epoch = bid.message.slot.epoch(E::slots_per_epoch());
        let column = data_columns.first().cloned().expect("should have column");

        cache
            .put_rpc_custody_columns(block_root, bid, vec![column])
            .expect("should put columns");

        assert_eq!(cache.block_cache_size(), 1);
        cache
            .do_maintenance(block_epoch + 1)
            .expect("maintenance should succeed");
        assert_eq!(cache.block_cache_size(), 0);
    }
}
