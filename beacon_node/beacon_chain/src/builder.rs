use crate::beacon_chain::{
    BEACON_CHAIN_DB_KEY, ETH1_CACHE_DB_KEY, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY,
};
use crate::eth1_chain::{CachingEth1Backend, SszEth1};
use crate::events::NullEventHandler;
use crate::fork_choice::SszForkChoice;
use crate::head_tracker::HeadTracker;
use crate::persisted_beacon_chain::PersistedBeaconChain;
use crate::shuffling_cache::ShufflingCache;
use crate::snapshot_cache::{SnapshotCache, DEFAULT_SNAPSHOT_CACHE_SIZE};
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{
    BeaconChain, BeaconChainTypes, BeaconSnapshot, Eth1Chain, Eth1ChainBackend, EventHandler,
    ForkChoice,
};
use eth1::Config as Eth1Config;
use operation_pool::{OperationPool, PersistedOperationPool};
use proto_array_fork_choice::ProtoArrayForkChoice;
use slog::{info, Logger};
use slot_clock::{SlotClock, TestingSlotClock};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use types::{
    BeaconBlock, BeaconState, ChainSpec, EthSpec, Hash256, Signature, SignedBeaconBlock, Slot,
};

pub const PUBKEY_CACHE_FILENAME: &str = "pubkey_cache.ssz";

/// An empty struct used to "witness" all the `BeaconChainTypes` traits. It has no user-facing
/// functionality and only exists to satisfy the type system.
pub struct Witness<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>(
    PhantomData<(
        TStore,
        TStoreMigrator,
        TSlotClock,
        TEth1Backend,
        TEthSpec,
        TEventHandler,
    )>,
);

impl<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler> BeaconChainTypes
    for Witness<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    type Store = TStore;
    type StoreMigrator = TStoreMigrator;
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
    store: Option<Arc<T::Store>>,
    store_migrator: Option<T::StoreMigrator>,
    canonical_head: Option<BeaconSnapshot<T::EthSpec>>,
    /// The finalized checkpoint to anchor the chain. May be genesis or a higher
    /// checkpoint.
    pub finalized_snapshot: Option<BeaconSnapshot<T::EthSpec>>,
    genesis_block_root: Option<Hash256>,
    op_pool: Option<OperationPool<T::EthSpec>>,
    fork_choice: Option<ForkChoice<T>>,
    eth1_chain: Option<Eth1Chain<T::Eth1Chain, T::EthSpec, T::Store>>,
    event_handler: Option<T::EventHandler>,
    slot_clock: Option<T::SlotClock>,
    head_tracker: Option<HeadTracker>,
    data_dir: Option<PathBuf>,
    pubkey_cache_path: Option<PathBuf>,
    validator_pubkey_cache: Option<ValidatorPubkeyCache>,
    spec: ChainSpec,
    disabled_forks: Vec<String>,
    log: Option<Logger>,
}

impl<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
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
            store_migrator: None,
            canonical_head: None,
            finalized_snapshot: None,
            genesis_block_root: None,
            op_pool: None,
            fork_choice: None,
            eth1_chain: None,
            event_handler: None,
            slot_clock: None,
            head_tracker: None,
            pubkey_cache_path: None,
            data_dir: None,
            disabled_forks: Vec::new(),
            validator_pubkey_cache: None,
            spec: TEthSpec::default_spec(),
            log: None,
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

    /// Sets the store (database).
    ///
    /// Should generally be called early in the build chain.
    pub fn store(mut self, store: Arc<TStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Sets the store migrator.
    pub fn store_migrator(mut self, store_migrator: TStoreMigrator) -> Self {
        self.store_migrator = Some(store_migrator);
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
            .get::<SszEth1>(&Hash256::from_slice(&ETH1_CACHE_DB_KEY))
            .map_err(|e| format!("DB error whilst reading eth1 cache: {:?}", e))
    }

    /// Returns true if `self.store` contains a persisted beacon chain.
    pub fn store_contains_beacon_chain(&self) -> Result<bool, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "load_from_store requires a store.".to_string())?;

        Ok(store
            .get::<PersistedBeaconChain>(&Hash256::from_slice(&BEACON_CHAIN_DB_KEY))
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
            .ok_or_else(|| "load_from_store requires a store.".to_string())?;

        let chain = store
            .get::<PersistedBeaconChain>(&Hash256::from_slice(&BEACON_CHAIN_DB_KEY))
            .map_err(|e| format!("DB error when reading persisted beacon chain: {:?}", e))?
            .ok_or_else(|| {
                "No persisted beacon chain found in store. Try deleting the .lighthouse/beacon dir."
                    .to_string()
            })?;

        self.genesis_block_root = Some(chain.genesis_block_root);
        self.head_tracker = Some(
            HeadTracker::from_ssz_container(&chain.ssz_head_tracker)
                .map_err(|e| format!("Failed to decode head tracker for database: {:?}", e))?,
        );

        let head_block_root = chain.canonical_head_block_root;
        let head_block = store
            .get::<SignedBeaconBlock<TEthSpec>>(&head_block_root)
            .map_err(|e| format!("DB error when reading head block: {:?}", e))?
            .ok_or_else(|| "Head block not found in store".to_string())?;
        let head_state_root = head_block.state_root();
        let head_state = store
            .get_state(&head_state_root, Some(head_block.slot()))
            .map_err(|e| format!("DB error when reading head state: {:?}", e))?
            .ok_or_else(|| "Head state not found in store".to_string())?;

        self.op_pool = Some(
            store
                .get::<PersistedOperationPool<TEthSpec>>(&Hash256::from_slice(&OP_POOL_DB_KEY))
                .map_err(|e| format!("DB error whilst reading persisted op pool: {:?}", e))?
                .map(|persisted| persisted.into_operation_pool(&head_state, &self.spec))
                .unwrap_or_else(|| OperationPool::new()),
        );

        let finalized_block_root = head_state.finalized_checkpoint.root;
        let finalized_block = store
            .get::<SignedBeaconBlock<TEthSpec>>(&finalized_block_root)
            .map_err(|e| format!("DB error when reading finalized block: {:?}", e))?
            .ok_or_else(|| "Finalized block not found in store".to_string())?;
        let finalized_state_root = finalized_block.state_root();
        let finalized_state = store
            .get_state(&finalized_state_root, Some(finalized_block.slot()))
            .map_err(|e| format!("DB error when reading finalized state: {:?}", e))?
            .ok_or_else(|| "Finalized state not found in store".to_string())?;

        self.finalized_snapshot = Some(BeaconSnapshot {
            beacon_block_root: finalized_block_root,
            beacon_block: finalized_block,
            beacon_state_root: finalized_state_root,
            beacon_state: finalized_state,
        });

        self.canonical_head = Some(BeaconSnapshot {
            beacon_block_root: head_block_root,
            beacon_block: head_block,
            beacon_state_root: head_state_root,
            beacon_state: head_state,
        });

        let pubkey_cache = ValidatorPubkeyCache::load_from_file(pubkey_cache_path)
            .map_err(|e| format!("Unable to open persisted pubkey cache: {:?}", e))?;

        self.validator_pubkey_cache = Some(pubkey_cache);

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

        self.genesis_block_root = Some(beacon_block_root);

        store
            .put_state(&beacon_state_root, &beacon_state)
            .map_err(|e| format!("Failed to store genesis state: {:?}", e))?;
        store
            .put(&beacon_block_root, &beacon_block)
            .map_err(|e| format!("Failed to store genesis block: {:?}", e))?;

        // Store the genesis block under the `ZERO_HASH` key.
        store.put(&Hash256::zero(), &beacon_block).map_err(|e| {
            format!(
                "Failed to store genesis block under 0x00..00 alias: {:?}",
                e
            )
        })?;

        self.finalized_snapshot = Some(BeaconSnapshot {
            beacon_block_root,
            beacon_block,
            beacon_state_root,
            beacon_state,
        });

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

    /// Creates a new, empty operation pool.
    fn empty_op_pool(mut self) -> Self {
        self.op_pool = Some(OperationPool::new());
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
            Witness<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>,
        >,
        String,
    > {
        let log = self
            .log
            .ok_or_else(|| "Cannot build without a logger".to_string())?;

        // If this beacon chain is being loaded from disk, use the stored head. Otherwise, just use
        // the finalized checkpoint (which is probably genesis).
        let mut canonical_head = if let Some(head) = self.canonical_head {
            head
        } else {
            self.finalized_snapshot
                .ok_or_else(|| "Cannot build without a state".to_string())?
        };

        canonical_head
            .beacon_state
            .build_all_caches(&self.spec)
            .map_err(|e| format!("Failed to build state caches: {:?}", e))?;

        if canonical_head.beacon_block.state_root() != canonical_head.beacon_state_root {
            return Err("beacon_block.state_root != beacon_state".to_string());
        }

        let pubkey_cache_path = self
            .pubkey_cache_path
            .ok_or_else(|| "Cannot build without a pubkey cache path".to_string())?;

        let validator_pubkey_cache = self
            .validator_pubkey_cache
            .map(|cache| Ok(cache))
            .unwrap_or_else(|| {
                ValidatorPubkeyCache::new(&canonical_head.beacon_state, pubkey_cache_path)
                    .map_err(|e| format!("Unable to init validator pubkey cache: {:?}", e))
            })?;

        let beacon_chain = BeaconChain {
            spec: self.spec,
            store: self
                .store
                .ok_or_else(|| "Cannot build without store".to_string())?,
            store_migrator: self
                .store_migrator
                .ok_or_else(|| "Cannot build without store migrator".to_string())?,
            slot_clock: self
                .slot_clock
                .ok_or_else(|| "Cannot build without slot clock".to_string())?,
            op_pool: self
                .op_pool
                .ok_or_else(|| "Cannot build without op pool".to_string())?,
            // TODO: allow for persisting and loading the pool from disk.
            naive_aggregation_pool: <_>::default(),
            eth1_chain: self.eth1_chain,
            genesis_validators_root: canonical_head.beacon_state.genesis_validators_root,
            canonical_head: TimeoutRwLock::new(canonical_head.clone()),
            genesis_block_root: self
                .genesis_block_root
                .ok_or_else(|| "Cannot build without a genesis block root".to_string())?,
            fork_choice: self
                .fork_choice
                .ok_or_else(|| "Cannot build without a fork choice".to_string())?,
            event_handler: self
                .event_handler
                .ok_or_else(|| "Cannot build without an event handler".to_string())?,
            head_tracker: self.head_tracker.unwrap_or_default(),
            snapshot_cache: TimeoutRwLock::new(SnapshotCache::new(
                DEFAULT_SNAPSHOT_CACHE_SIZE,
                canonical_head,
            )),
            shuffling_cache: TimeoutRwLock::new(ShufflingCache::new()),
            validator_pubkey_cache: TimeoutRwLock::new(validator_pubkey_cache),
            disabled_forks: self.disabled_forks,
            log: log.clone(),
        };

        let head = beacon_chain
            .head()
            .map_err(|e| format!("Failed to get head: {:?}", e))?;

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

impl<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Initializes a fork choice with the `ThreadSafeReducedTree` backend.
    ///
    /// If this builder is being "resumed" from disk, then rebuild the last fork choice stored to
    /// the database. Otherwise, create a new, empty fork choice.
    pub fn reduced_tree_fork_choice(mut self) -> Result<Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "reduced_tree_fork_choice requires a store.".to_string())?;

        let persisted_fork_choice = store
            .get::<SszForkChoice>(&Hash256::from_slice(&FORK_CHOICE_DB_KEY))
            .map_err(|e| format!("DB error when reading persisted fork choice: {:?}", e))?;

        let fork_choice = if let Some(persisted) = persisted_fork_choice {
            ForkChoice::from_ssz_container(persisted)
                .map_err(|e| format!("Unable to read persisted fork choice from disk: {:?}", e))?
        } else {
            let finalized_snapshot = &self
                .finalized_snapshot
                .as_ref()
                .ok_or_else(|| "fork_choice_backend requires a finalized_snapshot")?;
            let genesis_block_root = self
                .genesis_block_root
                .ok_or_else(|| "fork_choice_backend requires a genesis_block_root")?;

            let backend = ProtoArrayForkChoice::new(
                finalized_snapshot.beacon_block.message.slot,
                finalized_snapshot.beacon_block.message.state_root,
                // Note: here we set the `justified_epoch` to be the same as the epoch of the
                // finalized checkpoint. Whilst this finalized checkpoint may actually point to
                // a _later_ justified checkpoint, that checkpoint won't yet exist in the fork
                // choice.
                finalized_snapshot.beacon_state.current_epoch(),
                finalized_snapshot.beacon_state.current_epoch(),
                finalized_snapshot.beacon_block_root,
            )?;

            ForkChoice::new(
                backend,
                genesis_block_root,
                &finalized_snapshot.beacon_state,
            )
        };

        self.fork_choice = Some(fork_choice);

        Ok(self)
    }
}

impl<TStore, TStoreMigrator, TSlotClock, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            CachingEth1Backend<TEthSpec, TStore>,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
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
        let store = self
            .store
            .clone()
            .ok_or_else(|| "dummy_eth1_backend requires a store.".to_string())?;

        let backend = CachingEth1Backend::new(Eth1Config::default(), log.clone(), store);

        let mut eth1_chain = Eth1Chain::new(backend);
        eth1_chain.use_dummy_backend = true;

        self.eth1_chain = Some(eth1_chain);

        Ok(self)
    }
}

impl<TStore, TStoreMigrator, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<TStore, TStoreMigrator, TestingSlotClock, TEth1Backend, TEthSpec, TEventHandler>,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Sets the `BeaconChain` slot clock to `TestingSlotClock`.
    ///
    /// Requires the state to be initialized.
    pub fn testing_slot_clock(self, slot_duration: Duration) -> Result<Self, String> {
        let genesis_time = self
            .finalized_snapshot
            .as_ref()
            .ok_or_else(|| "testing_slot_clock requires an initialized state")?
            .beacon_state
            .genesis_time;

        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(genesis_time),
            slot_duration,
        );

        Ok(self.slot_clock(slot_clock))
    }
}

impl<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec>
    BeaconChainBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            NullEventHandler<TEthSpec>,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
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
        signature: Signature::empty_signature(),
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
    use store::{migrate::NullMigrator, MemoryStore};
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
        let store = Arc::new(MemoryStore::open());
        let spec = MinimalEthSpec::default_spec();
        let data_dir = tempdir().expect("should create temporary data_dir");

        let genesis_state = interop_genesis_state(
            &generate_deterministic_keypairs(validator_count),
            genesis_time,
            &spec,
        )
        .expect("should create interop genesis state");

        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(store)
            .store_migrator(NullMigrator)
            .data_dir(data_dir.path().to_path_buf())
            .genesis_state(genesis_state)
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build the dummy eth1 backend")
            .null_event_handler()
            .testing_slot_clock(Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
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
