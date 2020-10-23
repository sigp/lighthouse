use crate::beacon_chain::{
    BEACON_CHAIN_DB_KEY, ETH1_CACHE_DB_KEY, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY,
};
use crate::eth1_chain::{CachingEth1Backend, SszEth1};
use crate::events::NullEventHandler;
use crate::head_tracker::HeadTracker;
use crate::migrate::{BackgroundMigrator, MigratorConfig};
use crate::persisted_beacon_chain::PersistedBeaconChain;
use crate::persisted_fork_choice::PersistedForkChoice;
use crate::shuffling_cache::ShufflingCache;
use crate::snapshot_cache::{SnapshotCache, DEFAULT_SNAPSHOT_CACHE_SIZE};
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::ChainConfig;
use crate::{
    BeaconChain, BeaconChainTypes, BeaconForkChoiceStore, BeaconSnapshot, Eth1Chain,
    Eth1ChainBackend, EventHandler,
};
use eth1::Config as Eth1Config;
use fork_choice::ForkChoice;
use futures::channel::mpsc::Sender;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::RwLock;
use slog::{crit, info, Logger};
use slot_clock::{SlotClock, TestingSlotClock};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::{HotColdDB, ItemStore};
use types::{
    BeaconBlock, BeaconState, ChainSpec, EthSpec, Graffiti, Hash256, Signature, SignedBeaconBlock,
    Slot,
};

pub const PUBKEY_CACHE_FILENAME: &str = "pubkey_cache.ssz";

/// An empty struct used to "witness" all the `BeaconChainTypes` traits. It has no user-facing
/// functionality and only exists to satisfy the type system.
pub struct Witness<TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>(
    PhantomData<(
        TSlotClock,
        TEth1Backend,
        TEthSpec,
        TEventHandler,
        THotStore,
        TColdStore,
    )>,
);

impl<TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore> BeaconChainTypes
    for Witness<TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    type HotStore = THotStore;
    type ColdStore = TColdStore;
    type SlotClock = TSlotClock;
    type Eth1Chain = TEth1Backend;
    type EthSpec = TEthSpec;
    type EventHandler = TEventHandler;
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
    event_handler: Option<T::EventHandler>,
    slot_clock: Option<T::SlotClock>,
    shutdown_sender: Option<Sender<&'static str>>,
    head_tracker: Option<HeadTracker>,
    data_dir: Option<PathBuf>,
    pubkey_cache_path: Option<PathBuf>,
    validator_pubkey_cache: Option<ValidatorPubkeyCache>,
    spec: ChainSpec,
    chain_config: ChainConfig,
    disabled_forks: Vec<String>,
    log: Option<Logger>,
    graffiti: Graffiti,
}

impl<TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>
    BeaconChainBuilder<
        Witness<TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>,
    >
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
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
            event_handler: None,
            slot_clock: None,
            shutdown_sender: None,
            head_tracker: None,
            pubkey_cache_path: None,
            data_dir: None,
            disabled_forks: Vec::new(),
            validator_pubkey_cache: None,
            spec: TEthSpec::default_spec(),
            chain_config: ChainConfig::default(),
            log: None,
            graffiti: Graffiti::default(),
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

    /// Sets the maximum number of blocks that will be skipped when processing
    /// some consensus messages.
    ///
    /// Set to `None` for no limit.
    pub fn import_max_skip_slots(mut self, n: Option<u64>) -> Self {
        self.chain_config.import_max_skip_slots = n;
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

    /// Sets the logger.
    ///
    /// Should generally be called early in the build chain.
    pub fn logger(mut self, logger: Logger) -> Self {
        self.log = Some(logger);
        self
    }

    /// Sets the location to the pubkey cache file.
    ///
    /// Should generally be called early in the build chain.
    pub fn data_dir(mut self, path: PathBuf) -> Self {
        self.pubkey_cache_path = Some(path.join(PUBKEY_CACHE_FILENAME));
        self.data_dir = Some(path);
        self
    }

    /// Sets a list of hard-coded forks that will not be activated.
    pub fn disabled_forks(mut self, disabled_forks: Vec<String>) -> Self {
        self.disabled_forks = disabled_forks;
        self
    }

    /// Attempt to load an existing eth1 cache from the builder's `Store`.
    pub fn get_persisted_eth1_backend(&self) -> Result<Option<SszEth1>, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "get_persisted_eth1_backend requires a store.".to_string())?;

        store
            .get_item::<SszEth1>(&ETH1_CACHE_DB_KEY)
            .map_err(|e| format!("DB error whilst reading eth1 cache: {:?}", e))
    }

    /// Returns true if `self.store` contains a persisted beacon chain.
    pub fn store_contains_beacon_chain(&self) -> Result<bool, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "store_contains_beacon_chain requires a store.".to_string())?;

        Ok(store
            .get_item::<PersistedBeaconChain>(&BEACON_CHAIN_DB_KEY)
            .map_err(|e| format!("DB error when reading persisted beacon chain: {:?}", e))?
            .is_some())
    }

    /// Attempt to load an existing chain from the builder's `Store`.
    ///
    /// May initialize several components; including the op_pool and finalized checkpoints.
    pub fn resume_from_db(mut self) -> Result<Self, String> {
        let log = self
            .log
            .as_ref()
            .ok_or_else(|| "resume_from_db requires a log".to_string())?;

        let pubkey_cache_path = self
            .pubkey_cache_path
            .as_ref()
            .ok_or_else(|| "resume_from_db requires a data_dir".to_string())?;

        info!(
            log,
            "Starting beacon chain";
            "method" => "resume"
        );

        let store = self
            .store
            .clone()
            .ok_or_else(|| "resume_from_db requires a store.".to_string())?;

        let chain = store
            .get_item::<PersistedBeaconChain>(&BEACON_CHAIN_DB_KEY)
            .map_err(|e| format!("DB error when reading persisted beacon chain: {:?}", e))?
            .ok_or_else(|| {
                "No persisted beacon chain found in store. Try purging the beacon chain database."
                    .to_string()
            })?;

        let persisted_fork_choice = store
            .get_item::<PersistedForkChoice>(&FORK_CHOICE_DB_KEY)
            .map_err(|e| format!("DB error when reading persisted fork choice: {:?}", e))?
            .ok_or_else(|| "No persisted fork choice present in database.".to_string())?;

        let fc_store = BeaconForkChoiceStore::from_persisted(
            persisted_fork_choice.fork_choice_store,
            store.clone(),
        )
        .map_err(|e| format!("Unable to load ForkChoiceStore: {:?}", e))?;

        let fork_choice =
            ForkChoice::from_persisted(persisted_fork_choice.fork_choice, fc_store)
                .map_err(|e| format!("Unable to parse persisted fork choice from disk: {:?}", e))?;

        let genesis_block = store
            .get_item::<SignedBeaconBlock<TEthSpec>>(&chain.genesis_block_root)
            .map_err(|e| format!("DB error when reading genesis block: {:?}", e))?
            .ok_or_else(|| "Genesis block not found in store".to_string())?;
        let genesis_state = store
            .get_state(&genesis_block.state_root(), Some(genesis_block.slot()))
            .map_err(|e| format!("DB error when reading genesis state: {:?}", e))?
            .ok_or_else(|| "Genesis block not found in store".to_string())?;

        self.genesis_time = Some(genesis_state.genesis_time);

        self.op_pool = Some(
            store
                .get_item::<PersistedOperationPool<TEthSpec>>(&OP_POOL_DB_KEY)
                .map_err(|e| format!("DB error whilst reading persisted op pool: {:?}", e))?
                .map(PersistedOperationPool::into_operation_pool)
                .unwrap_or_else(OperationPool::new),
        );

        let pubkey_cache = ValidatorPubkeyCache::load_from_file(pubkey_cache_path)
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

    /// Starts a new chain from a genesis state.
    pub fn genesis_state(
        mut self,
        mut beacon_state: BeaconState<TEthSpec>,
    ) -> Result<Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "genesis_state requires a store")?;

        let beacon_block = genesis_block(&mut beacon_state, &self.spec)?;

        beacon_state
            .build_all_caches(&self.spec)
            .map_err(|e| format!("Failed to build genesis state caches: {:?}", e))?;

        let beacon_state_root = beacon_block.message.state_root;
        let beacon_block_root = beacon_block.canonical_root();

        self.genesis_state_root = Some(beacon_state_root);
        self.genesis_block_root = Some(beacon_block_root);

        store
            .put_state(&beacon_state_root, &beacon_state)
            .map_err(|e| format!("Failed to store genesis state: {:?}", e))?;
        store
            .put_item(&beacon_block_root, &beacon_block)
            .map_err(|e| format!("Failed to store genesis block: {:?}", e))?;

        // Store the genesis block under the `ZERO_HASH` key.
        store
            .put_item(&Hash256::zero(), &beacon_block)
            .map_err(|e| {
                format!(
                    "Failed to store genesis block under 0x00..00 alias: {:?}",
                    e
                )
            })?;

        let genesis = BeaconSnapshot {
            beacon_block_root,
            beacon_block,
            beacon_state_root,
            beacon_state,
        };

        let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store, &genesis);

        let fork_choice = ForkChoice::from_genesis(
            fc_store,
            genesis.beacon_block_root,
            &genesis.beacon_block.message,
            &genesis.beacon_state,
        )
        .map_err(|e| format!("Unable to build initialize ForkChoice: {:?}", e))?;

        self.fork_choice = Some(fork_choice);
        self.genesis_time = Some(genesis.beacon_state.genesis_time);

        Ok(self.empty_op_pool())
    }

    /// Sets the `BeaconChain` eth1 backend.
    pub fn eth1_backend(mut self, backend: Option<TEth1Backend>) -> Self {
        self.eth1_chain = backend.map(Eth1Chain::new);
        self
    }

    /// Sets the `BeaconChain` event handler backend.
    ///
    /// For example, provide `WebSocketSender` as a `handler`.
    pub fn event_handler(mut self, handler: TEventHandler) -> Self {
        self.event_handler = Some(handler);
        self
    }

    /// Sets the `BeaconChain` slot clock.
    ///
    /// For example, provide `SystemTimeSlotClock` as a `clock`.
    pub fn slot_clock(mut self, clock: TSlotClock) -> Self {
        self.slot_clock = Some(clock);
        self
    }

    /// Sets a `Sender` to allow the beacon chain to send shutdown signals.
    pub fn shutdown_sender(mut self, sender: Sender<&'static str>) -> Self {
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

    /// Consumes `self`, returning a `BeaconChain` if all required parameters have been supplied.
    ///
    /// An error will be returned at runtime if all required parameters have not been configured.
    ///
    /// Will also raise ambiguous type errors at compile time if some parameters have not been
    /// configured.
    #[allow(clippy::type_complexity)] // I think there's nothing to be gained here from a type alias.
    pub fn build(
        self,
    ) -> Result<
        BeaconChain<
            Witness<TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>,
        >,
        String,
    > {
        let log = self
            .log
            .ok_or_else(|| "Cannot build without a logger".to_string())?;
        let slot_clock = self
            .slot_clock
            .ok_or_else(|| "Cannot build without a slot_clock.".to_string())?;
        let store = self
            .store
            .clone()
            .ok_or_else(|| "Cannot build without a store.".to_string())?;
        let mut fork_choice = self
            .fork_choice
            .ok_or_else(|| "Cannot build without fork choice.".to_string())?;
        let genesis_block_root = self
            .genesis_block_root
            .ok_or_else(|| "Cannot build without a genesis block root".to_string())?;
        let genesis_state_root = self
            .genesis_state_root
            .ok_or_else(|| "Cannot build without a genesis state root".to_string())?;

        let current_slot = if slot_clock
            .is_prior_to_genesis()
            .ok_or_else(|| "Unable to read slot clock".to_string())?
        {
            self.spec.genesis_slot
        } else {
            slot_clock
                .now()
                .ok_or_else(|| "Unable to read slot".to_string())?
        };

        let head_block_root = fork_choice
            .get_head(current_slot)
            .map_err(|e| format!("Unable to get fork choice head: {:?}", e))?;

        let head_block = store
            .get_item::<SignedBeaconBlock<TEthSpec>>(&head_block_root)
            .map_err(|e| format!("DB error when reading head block: {:?}", e))?
            .ok_or_else(|| "Head block not found in store".to_string())?;
        let head_state_root = head_block.state_root();
        let head_state = store
            .get_state(&head_state_root, Some(head_block.slot()))
            .map_err(|e| format!("DB error when reading head state: {:?}", e))?
            .ok_or_else(|| "Head state not found in store".to_string())?;

        let mut canonical_head = BeaconSnapshot {
            beacon_block_root: head_block_root,
            beacon_block: head_block,
            beacon_state_root: head_state_root,
            beacon_state: head_state,
        };

        if canonical_head.beacon_block.state_root() != canonical_head.beacon_state_root {
            return Err("beacon_block.state_root != beacon_state".to_string());
        }

        canonical_head
            .beacon_state
            .build_all_caches(&self.spec)
            .map_err(|e| format!("Failed to build state caches: {:?}", e))?;

        // Perform a check to ensure that the finalization points of the head and fork choice are
        // consistent.
        //
        // This is a sanity check to detect database corruption.
        let fc_finalized = fork_choice.finalized_checkpoint();
        let head_finalized = canonical_head.beacon_state.finalized_checkpoint;
        if fc_finalized != head_finalized {
            if head_finalized.root == Hash256::zero()
                && head_finalized.epoch == fc_finalized.epoch
                && fc_finalized.root == genesis_block_root
            {
                // This is a legal edge-case encountered during genesis.
            } else {
                return Err(format!(
                    "Database corrupt: fork choice is finalized at {:?} whilst head is finalized at \
                    {:?}",
                    fc_finalized, head_finalized
                ));
            }
        }

        let pubkey_cache_path = self
            .pubkey_cache_path
            .ok_or_else(|| "Cannot build without a pubkey cache path".to_string())?;

        let validator_pubkey_cache = self.validator_pubkey_cache.map(Ok).unwrap_or_else(|| {
            ValidatorPubkeyCache::new(&canonical_head.beacon_state, pubkey_cache_path)
                .map_err(|e| format!("Unable to init validator pubkey cache: {:?}", e))
        })?;

        let migrator_config = self.store_migrator_config.unwrap_or_default();
        let store_migrator = BackgroundMigrator::new(
            store.clone(),
            migrator_config,
            genesis_block_root,
            log.clone(),
        );

        let beacon_chain = BeaconChain {
            spec: self.spec,
            config: self.chain_config,
            store,
            store_migrator,
            slot_clock,
            op_pool: self
                .op_pool
                .ok_or_else(|| "Cannot build without op pool".to_string())?,
            // TODO: allow for persisting and loading the pool from disk.
            naive_aggregation_pool: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_attestations: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_attesters: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_aggregators: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_block_producers: <_>::default(),
            // TODO: allow for persisting and loading the pool from disk.
            observed_voluntary_exits: <_>::default(),
            observed_proposer_slashings: <_>::default(),
            observed_attester_slashings: <_>::default(),
            eth1_chain: self.eth1_chain,
            genesis_validators_root: canonical_head.beacon_state.genesis_validators_root,
            canonical_head: TimeoutRwLock::new(canonical_head.clone()),
            genesis_block_root,
            genesis_state_root,
            fork_choice: RwLock::new(fork_choice),
            event_handler: self
                .event_handler
                .ok_or_else(|| "Cannot build without an event handler".to_string())?,
            head_tracker: Arc::new(self.head_tracker.unwrap_or_default()),
            snapshot_cache: TimeoutRwLock::new(SnapshotCache::new(
                DEFAULT_SNAPSHOT_CACHE_SIZE,
                canonical_head,
            )),
            shuffling_cache: TimeoutRwLock::new(ShufflingCache::new()),
            validator_pubkey_cache: TimeoutRwLock::new(validator_pubkey_cache),
            disabled_forks: self.disabled_forks,
            shutdown_sender: self
                .shutdown_sender
                .ok_or_else(|| "Cannot build without a shutdown sender.".to_string())?,
            log: log.clone(),
            graffiti: self.graffiti,
        };

        let head = beacon_chain
            .head()
            .map_err(|e| format!("Failed to get head: {:?}", e))?;

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
                    "finalized_epoch" => format!("{}", head.beacon_state.finalized_checkpoint.epoch),
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
            "head_state" => format!("{}", head.beacon_state_root),
            "head_block" => format!("{}", head.beacon_block_root),
            "head_slot" => format!("{}", head.beacon_block.slot()),
        );

        Ok(beacon_chain)
    }
}

impl<TSlotClock, TEthSpec, TEventHandler, THotStore, TColdStore>
    BeaconChainBuilder<
        Witness<
            TSlotClock,
            CachingEth1Backend<TEthSpec>,
            TEthSpec,
            TEventHandler,
            THotStore,
            TColdStore,
        >,
    >
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
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
            .ok_or_else(|| "dummy_eth1_backend requires a log".to_string())?;

        let backend =
            CachingEth1Backend::new(Eth1Config::default(), log.clone(), self.spec.clone());

        self.eth1_chain = Some(Eth1Chain::new_dummy(backend));

        Ok(self)
    }
}

impl<TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>
    BeaconChainBuilder<
        Witness<TestingSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>,
    >
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Sets the `BeaconChain` slot clock to `TestingSlotClock`.
    ///
    /// Requires the state to be initialized.
    pub fn testing_slot_clock(self, slot_duration: Duration) -> Result<Self, String> {
        let genesis_time = self
            .genesis_time
            .ok_or_else(|| "testing_slot_clock requires an initialized state")?;

        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(genesis_time),
            slot_duration,
        );

        Ok(self.slot_clock(slot_clock))
    }
}

impl<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>
    BeaconChainBuilder<
        Witness<
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            NullEventHandler<TEthSpec>,
            THotStore,
            TColdStore,
        >,
    >
where
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Sets the `BeaconChain` event handler to `NullEventHandler`.
    pub fn null_event_handler(self) -> Self {
        let handler = NullEventHandler::default();
        self.event_handler(handler)
    }
}

fn genesis_block<T: EthSpec>(
    genesis_state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<SignedBeaconBlock<T>, String> {
    let mut genesis_block = SignedBeaconBlock {
        message: BeaconBlock::empty(&spec),
        // Empty signature, which should NEVER be read. This isn't to-spec, but makes the genesis
        // block consistent with every other block.
        signature: Signature::empty(),
    };
    genesis_block.message.state_root = genesis_state
        .update_tree_hash_cache()
        .map_err(|e| format!("Error hashing genesis state: {:?}", e))?;
    Ok(genesis_block)
}

#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use super::*;
    use eth2_hashing::hash;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use sloggers::{null::NullLoggerBuilder, Build};
    use ssz::Encode;
    use std::time::Duration;
    use store::config::StoreConfig;
    use store::{HotColdDB, MemoryStore};
    use tempfile::tempdir;
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
        let data_dir = tempdir().expect("should create temporary data_dir");

        let genesis_state = interop_genesis_state(
            &generate_deterministic_keypairs(validator_count),
            genesis_time,
            &spec,
        )
        .expect("should create interop genesis state");

        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);

        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(Arc::new(store))
            .data_dir(data_dir.path().to_path_buf())
            .genesis_state(genesis_state)
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build the dummy eth1 backend")
            .null_event_handler()
            .testing_slot_clock(Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .shutdown_sender(shutdown_tx)
            .build()
            .expect("should build");

        let head = chain.head().expect("should get head");

        let state = head.beacon_state;
        let block = head.beacon_block;

        assert_eq!(state.slot, Slot::new(0), "should start from genesis");
        assert_eq!(
            state.genesis_time, 13_371_337,
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
                .get_block(&Hash256::zero())
                .expect("should read db")
                .expect("should find genesis block"),
            block,
            "should store genesis block under zero hash alias"
        );
        assert_eq!(
            state.validators.len(),
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

        let state = interop_genesis_state::<TestEthSpec>(&keypairs, genesis_time, spec)
            .expect("should build state");

        assert_eq!(
            state.eth1_data.block_hash,
            Hash256::from_slice(&[0x42; 32]),
            "eth1 block hash should be co-ordinated junk"
        );

        assert_eq!(
            state.genesis_time, genesis_time,
            "genesis time should be as specified"
        );

        for b in &state.balances {
            assert_eq!(
                *b, spec.max_effective_balance,
                "validator balances should be max effective balance"
            );
        }

        for v in &state.validators {
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
            state.balances.len(),
            validator_count,
            "validator balances len should be correct"
        );

        assert_eq!(
            state.validators.len(),
            validator_count,
            "validator count should be correct"
        );
    }
}
