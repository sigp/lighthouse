use crate::checkpoint_cache::CheckPointCache;
use crate::eth1_chain::CachingEth1Backend;
use crate::events::NullEventHandler;
use crate::head_tracker::HeadTracker;
use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::{
    BeaconChain, BeaconChainTypes, CheckPoint, Eth1Chain, Eth1ChainBackend, EventHandler,
    ForkChoice,
};
use eth1::Config as Eth1Config;
use lmd_ghost::{LmdGhost, ThreadSafeReducedTree};
use operation_pool::OperationPool;
use slog::{info, Logger};
use slot_clock::{SlotClock, TestingSlotClock};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use store::{BlockRootTree, Store};
use types::{BeaconBlock, BeaconState, ChainSpec, EthSpec, Hash256, Slot};

/// An empty struct used to "witness" all the `BeaconChainTypes` traits. It has no user-facing
/// functionality and only exists to satisfy the type system.
pub struct Witness<
    TStore,
    TStoreMigrator,
    TSlotClock,
    TLmdGhost,
    TEth1Backend,
    TEthSpec,
    TEventHandler,
>(
    PhantomData<(
        TStore,
        TStoreMigrator,
        TSlotClock,
        TLmdGhost,
        TEth1Backend,
        TEthSpec,
        TEventHandler,
    )>,
);

impl<TStore, TStoreMigrator, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainTypes
    for Witness<
        TStore,
        TStoreMigrator,
        TSlotClock,
        TLmdGhost,
        TEth1Backend,
        TEthSpec,
        TEventHandler,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    type Store = TStore;
    type StoreMigrator = TStoreMigrator;
    type SlotClock = TSlotClock;
    type LmdGhost = TLmdGhost;
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
    /// The finalized checkpoint to anchor the chain. May be genesis or a higher
    /// checkpoint.
    pub finalized_checkpoint: Option<CheckPoint<T::EthSpec>>,
    genesis_block_root: Option<Hash256>,
    op_pool: Option<OperationPool<T::EthSpec>>,
    fork_choice: Option<ForkChoice<T>>,
    eth1_chain: Option<Eth1Chain<T::Eth1Chain, T::EthSpec, T::Store>>,
    event_handler: Option<T::EventHandler>,
    slot_clock: Option<T::SlotClock>,
    persisted_beacon_chain: Option<PersistedBeaconChain<T>>,
    head_tracker: Option<HeadTracker>,
    block_root_tree: Option<Arc<BlockRootTree>>,
    spec: ChainSpec,
    log: Option<Logger>,
}

impl<TStore, TStoreMigrator, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
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
            finalized_checkpoint: None,
            genesis_block_root: None,
            op_pool: None,
            fork_choice: None,
            eth1_chain: None,
            event_handler: None,
            slot_clock: None,
            persisted_beacon_chain: None,
            head_tracker: None,
            block_root_tree: None,
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

    /// Attempt to load an existing chain from the builder's `Store`.
    ///
    /// May initialize several components; including the op_pool and finalized checkpoints.
    pub fn resume_from_db(mut self, config: Eth1Config) -> Result<Self, String> {
        let log = self
            .log
            .as_ref()
            .ok_or_else(|| "resume_from_db requires a log".to_string())?;

        info!(
            log,
            "Starting beacon chain";
            "method" => "resume"
        );

        let store = self
            .store
            .clone()
            .ok_or_else(|| "load_from_store requires a store.".to_string())?;

        let key = Hash256::from_slice(&BEACON_CHAIN_DB_KEY.as_bytes());
        let p: PersistedBeaconChain<
            Witness<
                TStore,
                TStoreMigrator,
                TSlotClock,
                TLmdGhost,
                TEth1Backend,
                TEthSpec,
                TEventHandler,
            >,
        > = match store.get(&key) {
            Err(e) => {
                return Err(format!(
                    "DB error when reading persisted beacon chain: {:?}",
                    e
                ))
            }
            Ok(None) => return Err("No persisted beacon chain found in store".into()),
            Ok(Some(p)) => p,
        };

        self.op_pool = Some(
            p.op_pool
                .clone()
                .into_operation_pool(&p.canonical_head.beacon_state, &self.spec),
        );

        self.finalized_checkpoint = Some(p.finalized_checkpoint.clone());
        self.genesis_block_root = Some(p.genesis_block_root);
        self.head_tracker = Some(
            HeadTracker::from_ssz_container(&p.ssz_head_tracker)
                .map_err(|e| format!("Failed to decode head tracker for database: {:?}", e))?,
        );
        self.eth1_chain = match &p.eth1_cache {
            Some(cache) => Some(Eth1Chain::from_ssz_container(cache, config, store, log)?),
            None => None,
        };
        self.block_root_tree = Some(Arc::new(p.block_root_tree.clone().into()));
        self.persisted_beacon_chain = Some(p);

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

        let mut beacon_block = genesis_block(&beacon_state, &self.spec);

        beacon_state
            .build_all_caches(&self.spec)
            .map_err(|e| format!("Failed to build genesis state caches: {:?}", e))?;

        let beacon_state_root = beacon_state.canonical_root();
        beacon_block.state_root = beacon_state_root;
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

        self.block_root_tree = Some(Arc::new(BlockRootTree::new(
            beacon_block_root,
            beacon_block.slot,
        )));

        self.finalized_checkpoint = Some(CheckPoint {
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
            Witness<
                TStore,
                TStoreMigrator,
                TSlotClock,
                TLmdGhost,
                TEth1Backend,
                TEthSpec,
                TEventHandler,
            >,
        >,
        String,
    > {
        let log = self
            .log
            .ok_or_else(|| "Cannot build without a logger".to_string())?;

        // If this beacon chain is being loaded from disk, use the stored head. Otherwise, just use
        // the finalized checkpoint (which is probably genesis).
        let mut canonical_head = if let Some(persisted_beacon_chain) = self.persisted_beacon_chain {
            persisted_beacon_chain.canonical_head
        } else {
            self.finalized_checkpoint
                .ok_or_else(|| "Cannot build without a state".to_string())?
        };

        canonical_head
            .beacon_state
            .build_all_caches(&self.spec)
            .map_err(|e| format!("Failed to build state caches: {:?}", e))?;

        if canonical_head.beacon_block.state_root != canonical_head.beacon_state_root {
            return Err("beacon_block.state_root != beacon_state".to_string());
        }

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
            eth1_chain: self.eth1_chain,
            canonical_head: TimeoutRwLock::new(canonical_head),
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
            block_root_tree: self
                .block_root_tree
                .ok_or_else(|| "Cannot build without a block root tree".to_string())?,
            checkpoint_cache: CheckPointCache::default(),
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
            "head_slot" => format!("{}", head.beacon_block.slot),
        );

        Ok(beacon_chain)
    }
}

impl<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            ThreadSafeReducedTree<TStore, TEthSpec>,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
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
            .ok_or_else(|| "reduced_tree_fork_choice requires a store")?;

        let block_root_tree = self
            .block_root_tree
            .clone()
            .ok_or_else(|| "reduced_tree_fork_choice requires a block root tree")?;

        let fork_choice = if let Some(persisted_beacon_chain) = &self.persisted_beacon_chain {
            ForkChoice::from_ssz_container(
                persisted_beacon_chain.fork_choice.clone(),
                store.clone(),
                block_root_tree,
            )
            .map_err(|e| format!("Unable to decode fork choice from db: {:?}", e))?
        } else {
            let finalized_checkpoint = &self
                .finalized_checkpoint
                .as_ref()
                .ok_or_else(|| "fork_choice_backend requires a finalized_checkpoint")?;
            let genesis_block_root = self
                .genesis_block_root
                .ok_or_else(|| "fork_choice_backend requires a genesis_block_root")?;

            let backend = ThreadSafeReducedTree::new(
                store.clone(),
                block_root_tree,
                &finalized_checkpoint.beacon_block,
                finalized_checkpoint.beacon_block_root,
            );

            ForkChoice::new(backend, genesis_block_root, self.spec.genesis_slot)
        };

        self.fork_choice = Some(fork_choice);

        Ok(self)
    }
}

impl<TStore, TStoreMigrator, TSlotClock, TLmdGhost, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            CachingEth1Backend<TEthSpec, TStore>,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Sets the `BeaconChain` eth1 back-end to `CachingEth1Backend`.
    pub fn caching_eth1_backend(self, backend: CachingEth1Backend<TEthSpec, TStore>) -> Self {
        self.eth1_backend(Some(backend))
    }

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

impl<TStore, TStoreMigrator, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TestingSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Sets the `BeaconChain` slot clock to `TestingSlotClock`.
    ///
    /// Requires the state to be initialized.
    pub fn testing_slot_clock(self, slot_duration: Duration) -> Result<Self, String> {
        let genesis_time = self
            .finalized_checkpoint
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

impl<TStore, TStoreMigrator, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec>
    BeaconChainBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            NullEventHandler<TEthSpec>,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec> + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec, TStore> + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Sets the `BeaconChain` event handler to `NullEventHandler`.
    pub fn null_event_handler(self) -> Self {
        let handler = NullEventHandler::default();
        self.event_handler(handler)
    }
}

fn genesis_block<T: EthSpec>(genesis_state: &BeaconState<T>, spec: &ChainSpec) -> BeaconBlock<T> {
    let mut genesis_block = BeaconBlock::empty(&spec);

    genesis_block.state_root = genesis_state.canonical_root();

    genesis_block
}

#[cfg(test)]
mod test {
    use super::*;
    use eth2_hashing::hash;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use sloggers::{null::NullLoggerBuilder, Build};
    use ssz::Encode;
    use std::time::Duration;
    use store::{migrate::NullMigrator, MemoryStore};
    use types::{EthSpec, MinimalEthSpec, Slot};

    type TestEthSpec = MinimalEthSpec;

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    #[test]
    fn recent_genesis() {
        let validator_count = 8;
        let genesis_time = 13371337;

        let log = get_logger();
        let store = Arc::new(MemoryStore::open());
        let spec = MinimalEthSpec::default_spec();

        let genesis_state = interop_genesis_state(
            &generate_deterministic_keypairs(validator_count),
            genesis_time,
            &spec,
        )
        .expect("should create interop genesis state");

        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(store.clone())
            .store_migrator(NullMigrator)
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
            state.genesis_time, 13371337,
            "should have the correct genesis time"
        );
        assert_eq!(
            block.state_root,
            state.canonical_root(),
            "block should have correct state root"
        );
        assert_eq!(
            chain
                .store
                .get::<BeaconBlock<_>>(&Hash256::zero())
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
