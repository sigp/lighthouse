use crate::beacon_chain::{CanonicalHead, BEACON_CHAIN_DB_KEY, ETH1_CACHE_DB_KEY, OP_POOL_DB_KEY};
use crate::eth1_chain::{CachingEth1Backend, SszEth1};
use crate::eth1_finalization_cache::Eth1FinalizationCache;
use crate::fork_choice_signal::ForkChoiceSignalTx;
use crate::fork_revert::{reset_fork_choice_to_finalization, revert_to_fork_boundary};
use crate::head_tracker::HeadTracker;
use crate::migrate::{BackgroundMigrator, MigratorConfig};
use crate::persisted_beacon_chain::PersistedBeaconChain;
use crate::shuffling_cache::{BlockShufflingIds, ShufflingCache};
use crate::snapshot_cache::{SnapshotCache, DEFAULT_SNAPSHOT_CACHE_SIZE};
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::validator_monitor::ValidatorMonitor;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::ChainConfig;
use crate::{
    BeaconChain, BeaconChainTypes, BeaconForkChoiceStore, BeaconSnapshot, Eth1Chain,
    Eth1ChainBackend, ServerSentEventHandler,
};
use eth1::Config as Eth1Config;
use execution_layer::ExecutionLayer;
use fork_choice::{ForkChoice, ResetPayloadStatuses};
use futures::channel::mpsc::Sender;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::RwLock;
use proto_array::{DisallowedReOrgOffsets, ReOrgThreshold};
use slasher::Slasher;
use slog::{crit, debug, error, info, Logger};
use slot_clock::{SlotClock, TestingSlotClock};
use state_processing::per_slot_processing;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use store::{Error as StoreError, HotColdDB, ItemStore, KeyValueStoreOp};
use task_executor::{ShutdownReason, TaskExecutor};
use types::{
    BeaconBlock, BeaconState, ChainSpec, Checkpoint, Epoch, EthSpec, Graffiti, Hash256,
    PublicKeyBytes, Signature, SignedBeaconBlock, Slot,
};

/// An empty struct used to "witness" all the `BeaconChainTypes` traits. It has no user-facing
/// functionality and only exists to satisfy the type system.
pub struct Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>(
    PhantomData<(TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore)>,
);

impl<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore> BeaconChainTypes
    for Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    type HotStore = THotStore;
    type ColdStore = TColdStore;
    type SlotClock = TSlotClock;
    type Eth1Chain = TEth1Backend;
    type EthSpec = TEthSpec;
}

/// Builds a `BeaconChain` by either creating anew from genesis, or, resuming from an existing chain
/// persisted to `store`.
///
/// Types may be elided and the compiler will infer them if all necessary builder methods have been
/// called. If type inference errors are being raised, it is likely that not all required methods
/// have been called.
///
/// See the tests for an example of a complete working example.
pub struct BeaconChainBuilder<T: BeaconChainTypes> {
    #[allow(clippy::type_complexity)]
    store: Option<Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>>,
    store_migrator_config: Option<MigratorConfig>,
    pub genesis_time: Option<u64>,
    genesis_block_root: Option<Hash256>,
    genesis_state_root: Option<Hash256>,
    #[allow(clippy::type_complexity)]
    fork_choice: Option<
        ForkChoice<BeaconForkChoiceStore<T::EthSpec, T::HotStore, T::ColdStore>, T::EthSpec>,
    >,
    op_pool: Option<OperationPool<T::EthSpec>>,
    eth1_chain: Option<Eth1Chain<T::Eth1Chain, T::EthSpec>>,
    execution_layer: Option<ExecutionLayer<T::EthSpec>>,
    event_handler: Option<ServerSentEventHandler<T::EthSpec>>,
    slot_clock: Option<T::SlotClock>,
    shutdown_sender: Option<Sender<ShutdownReason>>,
    head_tracker: Option<HeadTracker>,
    validator_pubkey_cache: Option<ValidatorPubkeyCache<T>>,
    spec: ChainSpec,
    chain_config: ChainConfig,
    log: Option<Logger>,
    graffiti: Graffiti,
    slasher: Option<Arc<Slasher<T::EthSpec>>>,
    validator_monitor: Option<ValidatorMonitor<T::EthSpec>>,
    // Pending I/O batch that is constructed during building and should be executed atomically
    // alongside `PersistedBeaconChain` storage when `BeaconChainBuilder::build` is called.
    pending_io_batch: Vec<KeyValueStoreOp>,
    task_executor: Option<TaskExecutor>,
}

impl<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>
    BeaconChainBuilder<Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>>
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Returns a new builder.
    ///
    /// The `_eth_spec_instance` parameter is only supplied to make concrete the `TEthSpec` trait.
    /// This should generally be either the `MinimalEthSpec` or `MainnetEthSpec` types.
    pub fn new(_eth_spec_instance: TEthSpec) -> Self {
        Self {
            store: None,
            store_migrator_config: None,
            genesis_time: None,
            genesis_block_root: None,
            genesis_state_root: None,
            fork_choice: None,
            op_pool: None,
            eth1_chain: None,
            execution_layer: None,
            event_handler: None,
            slot_clock: None,
            shutdown_sender: None,
            head_tracker: None,
            validator_pubkey_cache: None,
            spec: TEthSpec::default_spec(),
            chain_config: ChainConfig::default(),
            log: None,
            graffiti: Graffiti::default(),
            slasher: None,
            validator_monitor: None,
            pending_io_batch: vec![],
            task_executor: None,
        }
    }

    /// Override the default spec (as defined by `TEthSpec`).
    ///
    /// This method should generally be called immediately after `Self::new` to ensure components
    /// are started with a consistent spec.
    pub fn custom_spec(mut self, spec: ChainSpec) -> Self {
        self.spec = spec;
        self
    }

    /// Get a reference to the builder's spec.
    pub fn get_spec(&self) -> &ChainSpec {
        &self.spec
    }

    /// Sets the maximum number of blocks that will be skipped when processing
    /// some consensus messages.
    ///
    /// Set to `None` for no limit.
    pub fn import_max_skip_slots(mut self, n: Option<u64>) -> Self {
        self.chain_config.import_max_skip_slots = n;
        self
    }

    /// Sets the proposer re-org threshold.
    pub fn proposer_re_org_threshold(mut self, threshold: Option<ReOrgThreshold>) -> Self {
        self.chain_config.re_org_threshold = threshold;
        self
    }

    /// Sets the proposer re-org max epochs since finalization.
    pub fn proposer_re_org_max_epochs_since_finalization(
        mut self,
        epochs_since_finalization: Epoch,
    ) -> Self {
        self.chain_config.re_org_max_epochs_since_finalization = epochs_since_finalization;
        self
    }

    /// Sets the proposer re-org disallowed offsets list.
    pub fn proposer_re_org_disallowed_offsets(
        mut self,
        disallowed_offsets: DisallowedReOrgOffsets,
    ) -> Self {
        self.chain_config.re_org_disallowed_offsets = disallowed_offsets;
        self
    }

    /// Sets the store (database).
    ///
    /// Should generally be called early in the build chain.
    pub fn store(mut self, store: Arc<HotColdDB<TEthSpec, THotStore, TColdStore>>) -> Self {
        self.store = Some(store);
        self
    }

    /// Sets the store migrator config (optional).
    pub fn store_migrator_config(mut self, config: MigratorConfig) -> Self {
        self.store_migrator_config = Some(config);
        self
    }

    /// Sets the slasher.
    pub fn slasher(mut self, slasher: Arc<Slasher<TEthSpec>>) -> Self {
        self.slasher = Some(slasher);
        self
    }

    /// Sets the logger.
    ///
    /// Should generally be called early in the build chain.
    pub fn logger(mut self, log: Logger) -> Self {
        self.log = Some(log);
        self
    }

    /// Sets the task executor.
    pub fn task_executor(mut self, task_executor: TaskExecutor) -> Self {
        self.task_executor = Some(task_executor);
        self
    }

    /// Attempt to load an existing eth1 cache from the builder's `Store`.
    pub fn get_persisted_eth1_backend(&self) -> Result<Option<SszEth1>, String> {
        let store = self
            .store
            .clone()
            .ok_or("get_persisted_eth1_backend requires a store.")?;

        store
            .get_item::<SszEth1>(&ETH1_CACHE_DB_KEY)
            .map_err(|e| format!("DB error whilst reading eth1 cache: {:?}", e))
    }

    /// Returns true if `self.store` contains a persisted beacon chain.
    pub fn store_contains_beacon_chain(&self) -> Result<bool, String> {
        let store = self
            .store
            .clone()
            .ok_or("store_contains_beacon_chain requires a store.")?;

        Ok(store
            .get_item::<PersistedBeaconChain>(&BEACON_CHAIN_DB_KEY)
            .map_err(|e| format!("DB error when reading persisted beacon chain: {:?}", e))?
            .is_some())
    }

    /// Attempt to load an existing chain from the builder's `Store`.
    ///
    /// May initialize several components; including the op_pool and finalized checkpoints.
    pub fn resume_from_db(mut self) -> Result<Self, String> {
        let log = self.log.as_ref().ok_or("resume_from_db requires a log")?;

        info!(
            log,
            "Starting beacon chain";
            "method" => "resume"
        );

        let store = self
            .store
            .clone()
            .ok_or("resume_from_db requires a store.")?;

        let chain = store
            .get_item::<PersistedBeaconChain>(&BEACON_CHAIN_DB_KEY)
            .map_err(|e| format!("DB error when reading persisted beacon chain: {:?}", e))?
            .ok_or_else(|| {
                "No persisted beacon chain found in store. Try purging the beacon chain database."
                    .to_string()
            })?;

        let fork_choice =
            BeaconChain::<Witness<TSlotClock, TEth1Backend, _, _, _>>::load_fork_choice(
                store.clone(),
                ResetPayloadStatuses::always_reset_conditionally(
                    self.chain_config.always_reset_payload_statuses,
                ),
                &self.spec,
                log,
            )
            .map_err(|e| format!("Unable to load fork choice from disk: {:?}", e))?
            .ok_or("Fork choice not found in store")?;

        let genesis_block = store
            .get_blinded_block(&chain.genesis_block_root)
            .map_err(|e| descriptive_db_error("genesis block", &e))?
            .ok_or("Genesis block not found in store")?;
        let genesis_state = store
            .get_state(&genesis_block.state_root(), Some(genesis_block.slot()))
            .map_err(|e| descriptive_db_error("genesis state", &e))?
            .ok_or("Genesis state not found in store")?;

        self.genesis_time = Some(genesis_state.genesis_time());

        self.op_pool = Some(
            store
                .get_item::<PersistedOperationPool<TEthSpec>>(&OP_POOL_DB_KEY)
                .map_err(|e| format!("DB error whilst reading persisted op pool: {:?}", e))?
                .map(PersistedOperationPool::into_operation_pool)
                .transpose()
                .map_err(|e| {
                    format!(
                        "Error while creating the op pool from the persisted op pool: {:?}",
                        e
                    )
                })?
                .unwrap_or_else(OperationPool::new),
        );

        let pubkey_cache = ValidatorPubkeyCache::load_from_store(store)
            .map_err(|e| format!("Unable to open persisted pubkey cache: {:?}", e))?;

        self.genesis_block_root = Some(chain.genesis_block_root);
        self.genesis_state_root = Some(genesis_block.state_root());
        self.head_tracker = Some(
            HeadTracker::from_ssz_container(&chain.ssz_head_tracker)
                .map_err(|e| format!("Failed to decode head tracker for database: {:?}", e))?,
        );
        self.validator_pubkey_cache = Some(pubkey_cache);
        self.fork_choice = Some(fork_choice);

        Ok(self)
    }

    /// Store the genesis state & block in the DB.
    ///
    /// Do *not* initialize fork choice, or do anything that assumes starting from genesis.
    ///
    /// Return the `BeaconSnapshot` representing genesis as well as the mutated builder.
    fn set_genesis_state(
        mut self,
        mut beacon_state: BeaconState<TEthSpec>,
    ) -> Result<(BeaconSnapshot<TEthSpec>, Self), String> {
        let store = self
            .store
            .clone()
            .ok_or("set_genesis_state requires a store")?;

        let beacon_block = genesis_block(&mut beacon_state, &self.spec)?;

        beacon_state
            .build_caches(&self.spec)
            .map_err(|e| format!("Failed to build genesis state caches: {:?}", e))?;

        let beacon_state_root = beacon_block.message().state_root();
        let beacon_block_root = beacon_block.canonical_root();

        store
            .put_state(&beacon_state_root, &beacon_state)
            .map_err(|e| format!("Failed to store genesis state: {:?}", e))?;
        store
            .put_block(&beacon_block_root, beacon_block.clone())
            .map_err(|e| format!("Failed to store genesis block: {:?}", e))?;

        // Store the genesis block under the `ZERO_HASH` key.
        store
            .put_block(&Hash256::zero(), beacon_block.clone())
            .map_err(|e| {
                format!(
                    "Failed to store genesis block under 0x00..00 alias: {:?}",
                    e
                )
            })?;

        self.genesis_state_root = Some(beacon_state_root);
        self.genesis_block_root = Some(beacon_block_root);
        self.genesis_time = Some(beacon_state.genesis_time());

        Ok((
            BeaconSnapshot {
                beacon_block_root,
                beacon_block: Arc::new(beacon_block),
                beacon_state,
            },
            self,
        ))
    }

    /// Starts a new chain from a genesis state.
    pub fn genesis_state(mut self, beacon_state: BeaconState<TEthSpec>) -> Result<Self, String> {
        let store = self.store.clone().ok_or("genesis_state requires a store")?;

        let (genesis, updated_builder) = self.set_genesis_state(beacon_state)?;
        self = updated_builder;

        // Stage the database's metadata fields for atomic storage when `build` is called.
        // Since v4.4.0 we will set the anchor with a dummy state upper limit in order to prevent
        // historic states from being retained (unless `--reconstruct-historic-states` is set).
        let retain_historic_states = self.chain_config.reconstruct_historic_states;
        self.pending_io_batch.push(
            store
                .init_anchor_info(genesis.beacon_block.message(), retain_historic_states)
                .map_err(|e| format!("Failed to initialize genesis anchor: {:?}", e))?,
        );

        let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store, &genesis)
            .map_err(|e| format!("Unable to initialize fork choice store: {e:?}"))?;
        let current_slot = None;

        let fork_choice = ForkChoice::from_anchor(
            fc_store,
            genesis.beacon_block_root,
            &genesis.beacon_block,
            &genesis.beacon_state,
            current_slot,
            &self.spec,
        )
        .map_err(|e| format!("Unable to initialize ForkChoice: {:?}", e))?;

        self.fork_choice = Some(fork_choice);

        Ok(self.empty_op_pool())
    }

    /// Start the chain from a weak subjectivity state.
    pub fn weak_subjectivity_state(
        mut self,
        mut weak_subj_state: BeaconState<TEthSpec>,
        weak_subj_block: SignedBeaconBlock<TEthSpec>,
        genesis_state: BeaconState<TEthSpec>,
    ) -> Result<Self, String> {
        let store = self
            .store
            .clone()
            .ok_or("weak_subjectivity_state requires a store")?;
        let log = self
            .log
            .as_ref()
            .ok_or("weak_subjectivity_state requires a log")?;

        // Ensure the state is advanced to an epoch boundary.
        let slots_per_epoch = TEthSpec::slots_per_epoch();
        if weak_subj_state.slot() % slots_per_epoch != 0 {
            debug!(
                log,
                "Advancing checkpoint state to boundary";
                "state_slot" => weak_subj_state.slot(),
                "block_slot" => weak_subj_block.slot(),
            );
            while weak_subj_state.slot() % slots_per_epoch != 0 {
                per_slot_processing(&mut weak_subj_state, None, &self.spec)
                    .map_err(|e| format!("Error advancing state: {e:?}"))?;
            }
        }

        // Prime all caches before storing the state in the database and computing the tree hash
        // root.
        weak_subj_state
            .build_caches(&self.spec)
            .map_err(|e| format!("Error building caches on checkpoint state: {e:?}"))?;
        let weak_subj_state_root = weak_subj_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Error computing checkpoint state root: {:?}", e))?;

        let weak_subj_slot = weak_subj_state.slot();
        let weak_subj_block_root = weak_subj_block.canonical_root();

        // Validate the state's `latest_block_header` against the checkpoint block.
        let state_latest_block_root = weak_subj_state.get_latest_block_root(weak_subj_state_root);
        if weak_subj_block_root != state_latest_block_root {
            return Err(format!(
                "Snapshot state's most recent block root does not match block, expected: {:?}, got: {:?}",
                weak_subj_block_root, state_latest_block_root
            ));
        }

        // Check that the checkpoint state is for the same network as the genesis state.
        // This check doesn't do much for security but should prevent mistakes.
        if weak_subj_state.genesis_validators_root() != genesis_state.genesis_validators_root() {
            return Err(format!(
                "Snapshot state appears to be from the wrong network. Genesis validators root \
                 is {:?} but should be {:?}",
                weak_subj_state.genesis_validators_root(),
                genesis_state.genesis_validators_root()
            ));
        }

        // Set the store's split point *before* storing genesis so that genesis is stored
        // immediately in the freezer DB.
        store.set_split(weak_subj_slot, weak_subj_state_root, weak_subj_block_root);
        let (_, updated_builder) = self.set_genesis_state(genesis_state)?;
        self = updated_builder;

        // Fill in the linear block roots between the checkpoint block's slot and the aligned
        // state's slot. All slots less than the block's slot will be handled by block backfill,
        // while states greater or equal to the checkpoint state will be handled by `migrate_db`.
        let block_root_batch = store
            .store_frozen_block_root_at_skip_slots(
                weak_subj_block.slot(),
                weak_subj_state.slot(),
                weak_subj_block_root,
            )
            .map_err(|e| format!("Error writing frozen block roots: {e:?}"))?;
        store
            .cold_db
            .do_atomically(block_root_batch)
            .map_err(|e| format!("Error writing frozen block roots: {e:?}"))?;

        // Write the state and block non-atomically, it doesn't matter if they're forgotten
        // about on a crash restart.
        store
            .put_state(&weak_subj_state_root, &weak_subj_state)
            .map_err(|e| format!("Failed to store weak subjectivity state: {:?}", e))?;
        store
            .put_block(&weak_subj_block_root, weak_subj_block.clone())
            .map_err(|e| format!("Failed to store weak subjectivity block: {:?}", e))?;

        // Stage the database's metadata fields for atomic storage when `build` is called.
        // This prevents the database from restarting in an inconsistent state if the anchor
        // info or split point is written before the `PersistedBeaconChain`.
        let retain_historic_states = self.chain_config.reconstruct_historic_states;
        self.pending_io_batch.push(store.store_split_in_batch());
        self.pending_io_batch.push(
            store
                .init_anchor_info(weak_subj_block.message(), retain_historic_states)
                .map_err(|e| format!("Failed to initialize anchor info: {:?}", e))?,
        );

        // Store pruning checkpoint to prevent attempting to prune before the anchor state.
        self.pending_io_batch
            .push(store.pruning_checkpoint_store_op(Checkpoint {
                root: weak_subj_block_root,
                epoch: weak_subj_state.slot().epoch(TEthSpec::slots_per_epoch()),
            }));

        let snapshot = BeaconSnapshot {
            beacon_block_root: weak_subj_block_root,
            beacon_block: Arc::new(weak_subj_block),
            beacon_state: weak_subj_state,
        };

        let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store, &snapshot)
            .map_err(|e| format!("Unable to initialize fork choice store: {e:?}"))?;

        let fork_choice = ForkChoice::from_anchor(
            fc_store,
            snapshot.beacon_block_root,
            &snapshot.beacon_block,
            &snapshot.beacon_state,
            Some(weak_subj_slot),
            &self.spec,
        )
        .map_err(|e| format!("Unable to initialize ForkChoice: {:?}", e))?;

        self.fork_choice = Some(fork_choice);

        Ok(self.empty_op_pool())
    }

    /// Sets the `BeaconChain` eth1 backend.
    pub fn eth1_backend(mut self, backend: Option<TEth1Backend>) -> Self {
        self.eth1_chain = backend.map(Eth1Chain::new);
        self
    }

    /// Sets the `BeaconChain` execution layer.
    pub fn execution_layer(mut self, execution_layer: Option<ExecutionLayer<TEthSpec>>) -> Self {
        self.execution_layer = execution_layer;
        self
    }

    /// Sets the `BeaconChain` event handler backend.
    ///
    /// For example, provide `ServerSentEventHandler` as a `handler`.
    pub fn event_handler(mut self, handler: Option<ServerSentEventHandler<TEthSpec>>) -> Self {
        self.event_handler = handler;
        self
    }

    /// Sets the `BeaconChain` slot clock.
    ///
    /// For example, provide `SystemTimeSlotClock` as a `clock`.
    pub fn slot_clock(mut self, clock: TSlotClock) -> Self {
        self.slot_clock = Some(clock);
        self
    }

    /// Fetch a reference to the slot clock.
    ///
    /// Can be used for mutation during testing due to `SlotClock`'s internal mutability.
    pub fn get_slot_clock(&self) -> Option<&TSlotClock> {
        self.slot_clock.as_ref()
    }

    /// Sets a `Sender` to allow the beacon chain to send shutdown signals.
    pub fn shutdown_sender(mut self, sender: Sender<ShutdownReason>) -> Self {
        self.shutdown_sender = Some(sender);
        self
    }

    /// Creates a new, empty operation pool.
    fn empty_op_pool(mut self) -> Self {
        self.op_pool = Some(OperationPool::new());
        self
    }

    /// Sets the `graffiti` field.
    pub fn graffiti(mut self, graffiti: Graffiti) -> Self {
        self.graffiti = graffiti;
        self
    }

    /// Sets the `ChainConfig` that determines `BeaconChain` runtime behaviour.
    pub fn chain_config(mut self, config: ChainConfig) -> Self {
        self.chain_config = config;
        self
    }

    /// Register some validators for additional monitoring.
    ///
    /// `validators` is a comma-separated string of 0x-formatted BLS pubkeys.
    pub fn monitor_validators(
        mut self,
        auto_register: bool,
        validators: Vec<PublicKeyBytes>,
        individual_metrics_threshold: usize,
        log: Logger,
    ) -> Self {
        self.validator_monitor = Some(ValidatorMonitor::new(
            validators,
            auto_register,
            individual_metrics_threshold,
            log.clone(),
        ));
        self
    }

    /// Consumes `self`, returning a `BeaconChain` if all required parameters have been supplied.
    ///
    /// An error will be returned at runtime if all required parameters have not been configured.
    ///
    /// Will also raise ambiguous type errors at compile time if some parameters have not been
    /// configured.
    #[allow(clippy::type_complexity)] // I think there's nothing to be gained here from a type alias.
    pub fn build(
        mut self,
    ) -> Result<
        BeaconChain<Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>>,
        String,
    > {
        let log = self.log.ok_or("Cannot build without a logger")?;
        let slot_clock = self
            .slot_clock
            .ok_or("Cannot build without a slot_clock.")?;
        let store = self.store.clone().ok_or("Cannot build without a store.")?;
        let mut fork_choice = self
            .fork_choice
            .ok_or("Cannot build without fork choice.")?;
        let genesis_block_root = self
            .genesis_block_root
            .ok_or("Cannot build without a genesis block root")?;
        let genesis_state_root = self
            .genesis_state_root
            .ok_or("Cannot build without a genesis state root")?;
        let mut validator_monitor = self
            .validator_monitor
            .ok_or("Cannot build without a validator monitor")?;
        let head_tracker = Arc::new(self.head_tracker.unwrap_or_default());

        let current_slot = if slot_clock
            .is_prior_to_genesis()
            .ok_or("Unable to read slot clock")?
        {
            self.spec.genesis_slot
        } else {
            slot_clock.now().ok_or("Unable to read slot")?
        };

        let initial_head_block_root = fork_choice
            .get_head(current_slot, &self.spec)
            .map_err(|e| format!("Unable to get fork choice head: {:?}", e))?;

        // Try to decode the head block according to the current fork, if that fails, try
        // to backtrack to before the most recent fork.
        let (head_block_root, head_block, head_reverted) =
            match store.get_full_block(&initial_head_block_root) {
                Ok(Some(block)) => (initial_head_block_root, block, false),
                Ok(None) => return Err("Head block not found in store".into()),
                Err(StoreError::SszDecodeError(_)) => {
                    error!(
                        log,
                        "Error decoding head block";
                        "message" => "This node has likely missed a hard fork. \
                                      It will try to revert the invalid blocks and keep running, \
                                      but any stray blocks and states will not be deleted. \
                                      Long-term you should consider re-syncing this node."
                    );
                    let (block_root, block) = revert_to_fork_boundary(
                        current_slot,
                        initial_head_block_root,
                        store.clone(),
                        &self.spec,
                        &log,
                    )?;

                    // Update head tracker.
                    head_tracker.register_block(block_root, block.parent_root(), block.slot());
                    (block_root, block, true)
                }
                Err(e) => return Err(descriptive_db_error("head block", &e)),
            };

        let (_head_state_root, head_state) = store
            .get_advanced_hot_state(head_block_root, current_slot, head_block.state_root())
            .map_err(|e| descriptive_db_error("head state", &e))?
            .ok_or("Head state not found in store")?;

        // If the head reverted then we need to reset fork choice using the new head's finalized
        // checkpoint.
        if head_reverted {
            fork_choice = reset_fork_choice_to_finalization(
                head_block_root,
                &head_state,
                store.clone(),
                Some(current_slot),
                &self.spec,
                self.chain_config.progressive_balances_mode,
                &log,
            )?;
        }

        let head_shuffling_ids = BlockShufflingIds::try_from_head(head_block_root, &head_state)?;

        let mut head_snapshot = BeaconSnapshot {
            beacon_block_root: head_block_root,
            beacon_block: Arc::new(head_block),
            beacon_state: head_state,
        };

        head_snapshot
            .beacon_state
            .build_caches(&self.spec)
            .map_err(|e| format!("Failed to build state caches: {:?}", e))?;

        // Perform a check to ensure that the finalization points of the head and fork choice are
        // consistent.
        //
        // This is a sanity check to detect database corruption.
        let fc_finalized = fork_choice.finalized_checkpoint();
        let head_finalized = head_snapshot.beacon_state.finalized_checkpoint();
        if fc_finalized.epoch < head_finalized.epoch {
            return Err(format!(
                "Database corrupt: fork choice is finalized at {:?} whilst head is finalized at \
                    {:?}",
                fc_finalized, head_finalized
            ));
        }

        let validator_pubkey_cache = self.validator_pubkey_cache.map(Ok).unwrap_or_else(|| {
            ValidatorPubkeyCache::new(&head_snapshot.beacon_state, store.clone())
                .map_err(|e| format!("Unable to init validator pubkey cache: {:?}", e))
        })?;

        let migrator_config = self.store_migrator_config.unwrap_or_default();
        let store_migrator = BackgroundMigrator::new(
            store.clone(),
            migrator_config,
            genesis_block_root,
            log.clone(),
        );

        if let Some(slot) = slot_clock.now() {
            validator_monitor.process_valid_state(
                slot.epoch(TEthSpec::slots_per_epoch()),
                &head_snapshot.beacon_state,
                &self.spec,
            );
        }

        // If enabled, set up the fork choice signaller.
        let (fork_choice_signal_tx, fork_choice_signal_rx) =
            if self.chain_config.fork_choice_before_proposal_timeout_ms != 0 {
                let tx = ForkChoiceSignalTx::new();
                let rx = tx.get_receiver();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };

        // Store the `PersistedBeaconChain` in the database atomically with the metadata so that on
        // restart we can correctly detect the presence of an initialized database.
        //
        // This *must* be stored before constructing the `BeaconChain`, so that its `Drop` instance
        // doesn't write a `PersistedBeaconChain` without the rest of the batch.
        self.pending_io_batch.push(BeaconChain::<
            Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>,
        >::persist_head_in_batch_standalone(
            genesis_block_root, &head_tracker
        ));
        self.pending_io_batch.push(BeaconChain::<
            Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>,
        >::persist_fork_choice_in_batch_standalone(
            &fork_choice
        ));
        store
            .hot_db
            .do_atomically(self.pending_io_batch)
            .map_err(|e| format!("Error writing chain & metadata to disk: {:?}", e))?;

        let genesis_validators_root = head_snapshot.beacon_state.genesis_validators_root();
        let genesis_time = head_snapshot.beacon_state.genesis_time();
        let head_for_snapshot_cache = head_snapshot.clone();
        let canonical_head = CanonicalHead::new(fork_choice, Arc::new(head_snapshot));
        let shuffling_cache_size = self.chain_config.shuffling_cache_size;

        // Calculate the weak subjectivity point in which to backfill blocks to.
        let genesis_backfill_slot = if self.chain_config.genesis_backfill {
            Slot::new(0)
        } else {
            let backfill_epoch_range = (self.spec.min_validator_withdrawability_delay
                + self.spec.churn_limit_quotient)
                .as_u64()
                / 2;
            match slot_clock.now() {
                Some(current_slot) => {
                    let genesis_backfill_epoch = current_slot
                        .epoch(TEthSpec::slots_per_epoch())
                        .saturating_sub(backfill_epoch_range);
                    genesis_backfill_epoch.start_slot(TEthSpec::slots_per_epoch())
                }
                None => {
                    // The slot clock cannot derive the current slot. We therefore assume we are
                    // at or prior to genesis and backfill should sync all the way to genesis.
                    Slot::new(0)
                }
            }
        };

        let beacon_chain = BeaconChain {
            spec: self.spec,
            config: self.chain_config,
            store,
            task_executor: self
                .task_executor
                .ok_or("Cannot build without task executor")?,
            store_migrator,
            slot_clock,
            op_pool: self.op_pool.ok_or("Cannot build without op pool")?,
            // TODO: allow for persisting and loading the pool from disk.
            naive_aggregation_pool: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            naive_sync_aggregation_pool: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_attestations: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_sync_contributions: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_gossip_attesters: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_block_attesters: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_sync_contributors: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_aggregators: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_sync_aggregators: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_block_producers: <_>::default(),
            observed_voluntary_exits: <_>::default(),
            observed_proposer_slashings: <_>::default(),
            observed_attester_slashings: <_>::default(),
            observed_bls_to_execution_changes: <_>::default(),
            latest_seen_finality_update: <_>::default(),
            latest_seen_optimistic_update: <_>::default(),
            eth1_chain: self.eth1_chain,
            execution_layer: self.execution_layer,
            genesis_validators_root,
            genesis_time,
            canonical_head,
            genesis_block_root,
            genesis_state_root,
            fork_choice_signal_tx,
            fork_choice_signal_rx,
            event_handler: self.event_handler,
            head_tracker,
            snapshot_cache: TimeoutRwLock::new(SnapshotCache::new(
                DEFAULT_SNAPSHOT_CACHE_SIZE,
                head_for_snapshot_cache,
            )),
            shuffling_cache: TimeoutRwLock::new(ShufflingCache::new(
                shuffling_cache_size,
                head_shuffling_ids,
                log.clone(),
            )),
            eth1_finalization_cache: TimeoutRwLock::new(Eth1FinalizationCache::new(log.clone())),
            beacon_proposer_cache: <_>::default(),
            block_times_cache: <_>::default(),
            pre_finalization_block_cache: <_>::default(),
            validator_pubkey_cache: TimeoutRwLock::new(validator_pubkey_cache),
            attester_cache: <_>::default(),
            early_attester_cache: <_>::default(),
            shutdown_sender: self
                .shutdown_sender
                .ok_or("Cannot build without a shutdown sender.")?,
            log: log.clone(),
            graffiti: self.graffiti,
            slasher: self.slasher.clone(),
            validator_monitor: RwLock::new(validator_monitor),
            genesis_backfill_slot,
        };

        let head = beacon_chain.head_snapshot();

        // Prime the attester cache with the head state.
        beacon_chain
            .attester_cache
            .maybe_cache_state(
                &head.beacon_state,
                head.beacon_block_root,
                &beacon_chain.spec,
            )
            .map_err(|e| format!("Failed to prime attester cache: {:?}", e))?;

        // Only perform the check if it was configured.
        if let Some(wss_checkpoint) = beacon_chain.config.weak_subjectivity_checkpoint {
            if let Err(e) = beacon_chain.verify_weak_subjectivity_checkpoint(
                wss_checkpoint,
                head.beacon_block_root,
                &head.beacon_state,
            ) {
                crit!(
                    log,
                    "Weak subjectivity checkpoint verification failed on startup!";
                    "head_block_root" => format!("{}", head.beacon_block_root),
                    "head_slot" => format!("{}", head.beacon_block.slot()),
                    "finalized_epoch" => format!("{}", head.beacon_state.finalized_checkpoint().epoch),
                    "wss_checkpoint_epoch" => format!("{}", wss_checkpoint.epoch),
                    "error" => format!("{:?}", e),
                );
                crit!(log, "You must use the `--purge-db` flag to clear the database and restart sync. You may be on a hostile network.");
                return Err(format!("Weak subjectivity verification failed: {:?}", e));
            }
        }

        info!(
            log,
            "Beacon chain initialized";
            "head_state" => format!("{}", head.beacon_state_root()),
            "head_block" => format!("{}", head.beacon_block_root),
            "head_slot" => format!("{}", head.beacon_block.slot()),
        );

        // Check for states to reconstruct (in the background).
        if beacon_chain.config.reconstruct_historic_states {
            beacon_chain.store_migrator.process_reconstruction();
        }

        // Prune finalized execution payloads in the background.
        if beacon_chain.store.get_config().prune_payloads {
            let store = beacon_chain.store.clone();
            let log = log.clone();
            beacon_chain.task_executor.spawn_blocking(
                move || {
                    if let Err(e) = store.try_prune_execution_payloads(false) {
                        error!(log, "Error pruning payloads in background"; "error" => ?e);
                    }
                },
                "prune_payloads_background",
            );
        }

        Ok(beacon_chain)
    }
}

impl<TSlotClock, TEthSpec, THotStore, TColdStore>
    BeaconChainBuilder<
        Witness<TSlotClock, CachingEth1Backend<TEthSpec>, TEthSpec, THotStore, TColdStore>,
    >
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Do not use any eth1 backend. The client will not be able to produce beacon blocks.
    pub fn no_eth1_backend(self) -> Self {
        self.eth1_backend(None)
    }

    /// Sets the `BeaconChain` eth1 back-end to produce predictably junk data when producing blocks.
    pub fn dummy_eth1_backend(mut self) -> Result<Self, String> {
        let log = self
            .log
            .as_ref()
            .ok_or("dummy_eth1_backend requires a log")?;

        let backend =
            CachingEth1Backend::new(Eth1Config::default(), log.clone(), self.spec.clone())?;

        self.eth1_chain = Some(Eth1Chain::new_dummy(backend));

        Ok(self)
    }
}

impl<TEth1Backend, TEthSpec, THotStore, TColdStore>
    BeaconChainBuilder<Witness<TestingSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>>
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Sets the `BeaconChain` slot clock to `TestingSlotClock`.
    ///
    /// Requires the state to be initialized.
    pub fn testing_slot_clock(self, slot_duration: Duration) -> Result<Self, String> {
        let genesis_time = self
            .genesis_time
            .ok_or("testing_slot_clock requires an initialized state")?;

        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(genesis_time),
            slot_duration,
        );

        Ok(self.slot_clock(slot_clock))
    }
}

fn genesis_block<T: EthSpec>(
    genesis_state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<SignedBeaconBlock<T>, String> {
    let mut genesis_block = BeaconBlock::empty(spec);
    *genesis_block.state_root_mut() = genesis_state
        .update_tree_hash_cache()
        .map_err(|e| format!("Error hashing genesis state: {:?}", e))?;

    Ok(SignedBeaconBlock::from_block(
        genesis_block,
        // Empty signature, which should NEVER be read. This isn't to-spec, but makes the genesis
        // block consistent with every other block.
        Signature::empty(),
    ))
}

// Helper function to return more useful errors when reading from the database.
fn descriptive_db_error(item: &str, error: &StoreError) -> String {
    let additional_info = if let StoreError::SszDecodeError(_) = error {
        "Ensure the data directory is not initialized for a different network. The \
        --purge-db flag can be used to permanently delete the existing data directory."
    } else {
        "Database corruption may be present. If the issue persists, use \
        --purge-db to permanently delete the existing data directory."
    };
    format!(
        "DB error when reading {}: {:?}. {}",
        item, error, additional_info
    )
}

#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::validator_monitor::DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD;
    use ethereum_hashing::hash;
    use genesis::{
        generate_deterministic_keypairs, interop_genesis_state, DEFAULT_ETH1_BLOCK_HASH,
    };
    use sloggers::{null::NullLoggerBuilder, Build};
    use ssz::Encode;
    use std::time::Duration;
    use store::config::StoreConfig;
    use store::{HotColdDB, MemoryStore};
    use task_executor::test_utils::TestRuntime;
    use types::{EthSpec, MinimalEthSpec, Slot};

    type TestEthSpec = MinimalEthSpec;

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    #[test]
    fn recent_genesis() {
        let validator_count = 1;
        let genesis_time = 13_371_337;

        let log = get_logger();
        let store: HotColdDB<
            MinimalEthSpec,
            MemoryStore<MinimalEthSpec>,
            MemoryStore<MinimalEthSpec>,
        > = HotColdDB::open_ephemeral(StoreConfig::default(), ChainSpec::minimal(), log.clone())
            .unwrap();
        let spec = MinimalEthSpec::default_spec();

        let genesis_state = interop_genesis_state(
            &generate_deterministic_keypairs(validator_count),
            genesis_time,
            Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
            None,
            &spec,
        )
        .expect("should create interop genesis state");

        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let runtime = TestRuntime::default();

        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(Arc::new(store))
            .task_executor(runtime.task_executor.clone())
            .genesis_state(genesis_state)
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build the dummy eth1 backend")
            .testing_slot_clock(Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .shutdown_sender(shutdown_tx)
            .monitor_validators(
                true,
                vec![],
                DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD,
                log.clone(),
            )
            .build()
            .expect("should build");

        let head = chain.head_snapshot();

        let state = &head.beacon_state;
        let block = &head.beacon_block;

        assert_eq!(state.slot(), Slot::new(0), "should start from genesis");
        assert_eq!(
            state.genesis_time(),
            13_371_337,
            "should have the correct genesis time"
        );
        assert_eq!(
            block.state_root(),
            state.canonical_root(),
            "block should have correct state root"
        );
        assert_eq!(
            chain
                .store
                .get_blinded_block(&Hash256::zero())
                .expect("should read db")
                .expect("should find genesis block"),
            block.clone_as_blinded(),
            "should store genesis block under zero hash alias"
        );
        assert_eq!(
            state.validators().len(),
            validator_count,
            "should have correct validator count"
        );
        assert_eq!(
            chain.genesis_block_root,
            block.canonical_root(),
            "should have correct genesis block root"
        );
    }

    #[test]
    fn interop_state() {
        let validator_count = 16;
        let genesis_time = 42;
        let spec = &TestEthSpec::default_spec();

        let keypairs = generate_deterministic_keypairs(validator_count);

        let state = interop_genesis_state::<TestEthSpec>(
            &keypairs,
            genesis_time,
            Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
            None,
            spec,
        )
        .expect("should build state");

        assert_eq!(
            state.eth1_data().block_hash,
            Hash256::from_slice(&[0x42; 32]),
            "eth1 block hash should be co-ordinated junk"
        );

        assert_eq!(
            state.genesis_time(),
            genesis_time,
            "genesis time should be as specified"
        );

        for b in state.balances() {
            assert_eq!(
                *b, spec.max_effective_balance,
                "validator balances should be max effective balance"
            );
        }

        for v in state.validators() {
            let creds = v.withdrawal_credentials.as_bytes();
            assert_eq!(
                creds[0], spec.bls_withdrawal_prefix_byte,
                "first byte of withdrawal creds should be bls prefix"
            );
            assert_eq!(
                &creds[1..],
                &hash(&v.pubkey.as_ssz_bytes())[1..],
                "rest of withdrawal creds should be pubkey hash"
            )
        }

        assert_eq!(
            state.balances().len(),
            validator_count,
            "validator balances len should be correct"
        );

        assert_eq!(
            state.validators().len(),
            validator_count,
            "validator count should be correct"
        );
    }
}
