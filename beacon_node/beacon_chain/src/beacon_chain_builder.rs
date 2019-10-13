use crate::events::NullEventHandler;
use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use crate::InteropEth1ChainBackend;
use crate::{
    BeaconChain, BeaconChainTypes, CheckPoint, Eth1Chain, Eth1ChainBackend, EventHandler,
    ForkChoice,
};
use eth2_hashing::hash;
use lighthouse_bootstrap::Bootstrapper;
use lmd_ghost::{LmdGhost, ThreadSafeReducedTree};
use merkle_proof::MerkleTree;
use operation_pool::OperationPool;
use parking_lot::RwLock;
use rayon::prelude::*;
use slog::{crit, info, Logger};
use slot_clock::{SlotClock, TestingSlotClock};
use ssz::{Decode, Encode};
use state_processing::initialize_beacon_state_from_eth1;
use std::fs::File;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use store::Store;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    test_utils::generate_deterministic_keypairs, BeaconBlock, BeaconState, ChainSpec, Deposit,
    DepositData, Domain, EthSpec, Fork, Hash256, Keypair, PublicKey, Signature, Slot,
};

/// Defines how the client should initialize a BeaconChain.
///
/// In general, there are two methods:
///  - resuming a new chain, or
///  - initializing a new one.
#[derive(Debug, Clone)]
pub enum BeaconChainStartMethod {
    /// Resume from an existing BeaconChain, loaded from the existing local database.
    Resume,
    /// Resume from an existing BeaconChain, loaded from the existing local database.
    Mainnet,
    /// Create a new beacon chain that can connect to mainnet.
    ///
    /// Set the genesis time to be the start of the previous 30-minute window.
    RecentGenesis {
        validator_count: usize,
        minutes: u64,
    },
    /// Create a new beacon chain with `genesis_time` and `validator_count` validators, all with well-known
    /// secret keys.
    Generated {
        validator_count: usize,
        genesis_time: u64,
    },
    /// Create a new beacon chain with `genesis_time` and initial deposits generated from `keypairs`.
    Keypairs {
        keypairs: Vec<Keypair>,
        genesis_time: u64,
    },
    /// Create a new beacon chain by loading a SSZ-encoded genesis state from a file.
    Ssz { file: PathBuf },
    /// Create a new beacon chain by using a HTTP server (running our REST-API) to load genesis and
    /// finalized states and blocks.
    HttpBootstrap { server: String, port: Option<u16> },
}

impl Default for BeaconChainStartMethod {
    /// Equivalent to `BeaconChainStartMethod::Resume`.
    fn default() -> Self {
        BeaconChainStartMethod::Resume
    }
}

/// Builds a `BeaconChain`, either creating anew from genesis or resuming from an existing chain
/// persisted to `store`.
///
/// Types may be elided and the compiler will infer them if all necessary builder methods have been
/// called. If type inference errors are being raised it is likely that not all sufficient methods
/// have been called.
///
/// See the tests for an example of a complete working example.
pub struct BeaconChainBuilder<T: BeaconChainTypes> {
    store: Option<Arc<T::Store>>,
    /// The finalized checkpoint that will be used to start the chain. May be genesis or a higher
    /// checkpoint.
    pub finalized_checkpoint: Option<CheckPoint<T::EthSpec>>,
    genesis_block_root: Option<Hash256>,
    op_pool: Option<OperationPool<T::EthSpec>>,
    fork_choice: Option<ForkChoice<T>>,
    eth1_chain: Option<Eth1Chain<T>>,
    event_handler: Option<T::EventHandler>,
    slot_clock: Option<T::SlotClock>,
    spec: ChainSpec,
    log: Option<Logger>,
}

impl<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>,
    >
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
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
            finalized_checkpoint: None,
            genesis_block_root: None,
            op_pool: None,
            fork_choice: None,
            eth1_chain: None,
            event_handler: None,
            slot_clock: None,
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

    /// Sets the logger.
    ///
    /// Should generally be called early in the build chain.
    pub fn logger(mut self, logger: Logger) -> Self {
        self.log = Some(logger);
        self
    }

    /// Initializes the `BeaconState` and `BeaconBlock` at either genesis, some finalized
    /// checkpoint or from a previous `BeaconChain` persisted to the `Store`.
    ///
    /// Requires the store and logger to have been specified earlier in the build chain.
    pub fn initialize_state(
        mut self,
        start_method: &BeaconChainStartMethod,
    ) -> Result<Self, String> {
        let log = self
            .log
            .clone()
            .ok_or_else(|| "initialize_state requires a logger".to_string())?;
        let store = self
            .store
            .clone()
            .ok_or_else(|| "initialize_state requires a store".to_string())?;

        match start_method {
            BeaconChainStartMethod::Resume => {
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
                    Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>,
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
                        .into_operation_pool(&p.canonical_head.beacon_state, &self.spec),
                );

                self.finalized_checkpoint = Some(p.canonical_head);
                self.genesis_block_root = Some(p.genesis_block_root);

                Ok(self)
            }
            BeaconChainStartMethod::Mainnet => {
                crit!(log, "No mainnet beacon chain startup specification.");
                return Err("Mainnet launch is not yet announced.".into());
            }
            BeaconChainStartMethod::RecentGenesis {
                validator_count,
                minutes,
            } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "validator_count" => validator_count,
                    "minutes" => minutes,
                    "method" => "recent"
                );

                let keypairs = generate_deterministic_keypairs(*validator_count);
                let genesis_time = recent_genesis_time(*minutes);
                let genesis_state = interop_genesis_state(&keypairs, genesis_time, &self.spec)?;
                let genesis_block = genesis_block(&genesis_state, &self.spec);

                self.start_from_genesis(&store, genesis_state, genesis_block)
            }
            BeaconChainStartMethod::Generated {
                validator_count,
                genesis_time,
            } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "validator_count" => validator_count,
                    "genesis_time" => genesis_time,
                    "method" => "quick"
                );

                let keypairs = generate_deterministic_keypairs(*validator_count);
                let genesis_state = interop_genesis_state(&keypairs, *genesis_time, &self.spec)?;
                let genesis_block = genesis_block(&genesis_state, &self.spec);

                self.start_from_genesis(&store, genesis_state, genesis_block)
            }
            BeaconChainStartMethod::Keypairs {
                keypairs,
                genesis_time,
            } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "validator_count" => keypairs.len(),
                    "genesis_time" => genesis_time,
                    "method" => "keypairs"
                );

                let genesis_state = interop_genesis_state(&keypairs, *genesis_time, &self.spec)?;
                let genesis_block = genesis_block(&genesis_state, &self.spec);

                self.start_from_genesis(&store, genesis_state, genesis_block)
            }
            BeaconChainStartMethod::Ssz { file } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "file" => format!("{:?}", file),
                    "method" => "ssz"
                );

                let mut file = File::open(file.clone()).map_err(|e| {
                    format!("Unable to open SSZ genesis state file {:?}: {:?}", file, e)
                })?;

                let mut bytes = vec![];
                file.read_to_end(&mut bytes)
                    .map_err(|e| format!("Failed to read SSZ file: {:?}", e))?;

                let genesis_state = BeaconState::from_ssz_bytes(&bytes)
                    .map_err(|e| format!("Unable to parse SSZ genesis state file: {:?}", e))?;
                let genesis_block = genesis_block(&genesis_state, &self.spec);

                self.start_from_genesis(&store, genesis_state, genesis_block)
            }
            BeaconChainStartMethod::HttpBootstrap { server, port } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "port" => port,
                    "server" => server,
                    "method" => "bootstrap"
                );

                let bootstrapper = Bootstrapper::connect(server.to_string(), &log)
                    .map_err(|e| format!("Failed to initialize bootstrap client: {}", e))?;

                let (genesis_state, genesis_block) = bootstrapper
                    .genesis()
                    .map_err(|e| format!("Failed to bootstrap genesis state: {}", e))?;

                self.start_from_genesis(&store, genesis_state, genesis_block)
            }
        }
    }

    /// Starts a new chain from genesis.
    fn start_from_genesis(
        mut self,
        store: &TStore,
        mut beacon_state: BeaconState<TEthSpec>,
        mut beacon_block: BeaconBlock<TEthSpec>,
    ) -> Result<Self, String> {
        beacon_state
            .build_all_caches(&self.spec)
            .map_err(|e| format!("Failed to build genesis state caches: {:?}", e))?;

        let beacon_state_root = beacon_state.canonical_root();
        beacon_block.state_root = beacon_state_root;
        let beacon_block_root = beacon_block.canonical_root();

        self.genesis_block_root = Some(beacon_block_root);

        store
            .put(&beacon_state_root, &beacon_state)
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

        self.finalized_checkpoint = Some(CheckPoint {
            beacon_block_root,
            beacon_block,
            beacon_state_root,
            beacon_state,
        });

        Ok(self)
    }

    /// Sets the `BeaconChain` fork choice back-end.
    ///
    /// Requires the store and state to have been specified earlier in the build chain.
    ///
    /// For example, provide `ThreadSafeReducedTree` as a `backend`.
    pub fn fork_choice_backend(mut self, backend: TLmdGhost) -> Result<Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "reduced_tree_fork_choice requires a store")?;
        let genesis_block_root = self
            .genesis_block_root
            .ok_or_else(|| "fork_choice_backend requires a genesis_block_root")?;

        self.fork_choice = Some(ForkChoice::new(store, backend, genesis_block_root));

        Ok(self)
    }

    /// Sets the `BeaconChain` eth1 back-end.
    ///
    /// For example, provide `InteropEth1ChainBackend` as a `backend`.
    pub fn eth1_backend(mut self, backend: TEth1Backend) -> Self {
        self.eth1_chain = Some(Eth1Chain::new(backend));
        self
    }

    /// Sets the `BeaconChain` event handler back-end.
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
    pub fn empty_op_pool(mut self) -> Self {
        self.op_pool = Some(OperationPool::new());
        self
    }

    /// Consumes `self`, returning a `BeaconChain` if all required parameters have been supplied.
    ///
    /// An error will be returned at runtime if all required parameters have not been configured.
    /// Will also raise ambiguous type errors if some parameters have not been configured.
    pub fn build(
        self,
    ) -> Result<
        BeaconChain<Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>>,
        String,
    > {
        let mut canonical_head = self
            .finalized_checkpoint
            .ok_or_else(|| "Cannot build without a state".to_string())?;

        canonical_head
            .beacon_state
            .build_all_caches(&self.spec)
            .map_err(|e| format!("Failed to build state caches: {:?}", e))?;

        if canonical_head.beacon_block.state_root != canonical_head.beacon_state_root {
            return Err("beacon_block.state_root != beacon_state".to_string());
        }

        Ok(BeaconChain {
            spec: self.spec,
            store: self
                .store
                .ok_or_else(|| "Cannot build without store".to_string())?,
            slot_clock: self
                .slot_clock
                .ok_or_else(|| "Cannot build without slot clock".to_string())?,
            op_pool: self
                .op_pool
                .ok_or_else(|| "Cannot build without op pool".to_string())?,
            eth1_chain: self
                .eth1_chain
                .ok_or_else(|| "Cannot build without eth1 chain".to_string())?,
            canonical_head: RwLock::new(canonical_head),
            genesis_block_root: self
                .genesis_block_root
                .ok_or_else(|| "Cannot build without a genesis block root".to_string())?,
            fork_choice: self
                .fork_choice
                .ok_or_else(|| "Cannot build without a fork choice".to_string())?,
            event_handler: self
                .event_handler
                .ok_or_else(|| "Cannot build without an event handler".to_string())?,
            log: self
                .log
                .ok_or_else(|| "Cannot build without a logger".to_string())?,
        })
    }
}

impl<TStore, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<
            TStore,
            TSlotClock,
            ThreadSafeReducedTree<TStore, TEthSpec>,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Initializes a new, empty (no recorded votes or blocks) fork choice, using the
    /// `ThreadSafeReducedTree` backend.
    ///
    /// Equivalent to calling `Self::fork_choice_backend` with a new `ThreadSafeReducedTree`
    /// instance.
    ///
    /// Requires the store and state to be initialized.
    pub fn empty_reduced_tree_fork_choice(self) -> Result<Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "reduced_tree_fork_choice requires a store")?;
        let finalized_checkpoint = &self
            .finalized_checkpoint
            .clone()
            .expect("should have finalized checkpoint");

        let backend = ThreadSafeReducedTree::new(
            store.clone(),
            &finalized_checkpoint.beacon_block,
            finalized_checkpoint.beacon_block_root,
        );

        self.fork_choice_backend(backend)
    }
}

impl<TStore, TSlotClock, TLmdGhost, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<
            TStore,
            TSlotClock,
            TLmdGhost,
            InteropEth1ChainBackend<TEthSpec>,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Sets the `BeaconChain` eth1 back-end to `InteropEth1ChainBackend`.
    ///
    /// Equivalent to calling `Self::eth1_backend` with `InteropEth1ChainBackend`.
    pub fn interop_eth1_backend(self) -> Self {
        let backend = InteropEth1ChainBackend::default();
        self.eth1_backend(backend)
    }
}

impl<TStore, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    BeaconChainBuilder<
        Witness<TStore, TestingSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>,
    >
where
    TStore: Store + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Sets the `BeaconChain` slot clock to `TestingSlotClock`.
    ///
    /// Equivalent to calling `Self::slot_clock` with `TestingSlotClock`
    ///
    /// Requires the state to be initialized.
    pub fn testing_slot_clock(self, slot_duration: Duration) -> Result<Self, String> {
        let genesis_time = self
            .finalized_checkpoint
            .clone()
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

impl<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec>
    BeaconChainBuilder<
        Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, NullEventHandler<TEthSpec>>,
    >
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Sets the `BeaconChain` event handler to `NullEventHandler`.
    ///
    /// Equivalent to calling `Self::event_handler` with `NullEventHandler`
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

/// Builds a genesis state as defined by the Eth2 interop procedure (see below).
///
/// Reference:
/// https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start
fn interop_genesis_state<T: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    let eth1_block_hash = Hash256::from_slice(&[0x42; 32]);
    let eth1_timestamp = 2_u64.pow(40);
    let amount = spec.max_effective_balance;

    let withdrawal_credentials = |pubkey: &PublicKey| {
        let mut credentials = hash(&pubkey.as_ssz_bytes());
        credentials[0] = spec.bls_withdrawal_prefix_byte;
        Hash256::from_slice(&credentials)
    };

    let datas = keypairs
        .into_par_iter()
        .map(|keypair| {
            let mut data = DepositData {
                withdrawal_credentials: withdrawal_credentials(&keypair.pk),
                pubkey: keypair.pk.clone().into(),
                amount,
                signature: Signature::empty_signature().into(),
            };

            let domain = spec.get_domain(
                spec.genesis_slot.epoch(T::slots_per_epoch()),
                Domain::Deposit,
                &Fork::default(),
            );
            data.signature = Signature::new(&data.signed_root()[..], domain, &keypair.sk).into();

            data
        })
        .collect::<Vec<_>>();

    let deposit_root_leaves = datas
        .par_iter()
        .map(|data| Hash256::from_slice(&data.tree_hash_root()))
        .collect::<Vec<_>>();

    let mut proofs = vec![];
    for i in 1..=deposit_root_leaves.len() {
        // Note: this implementation is not so efficient.
        //
        // If `MerkleTree` had a push method, we could just build one tree and sample it instead of
        // rebuilding the tree for each deposit.
        let tree = MerkleTree::create(
            &deposit_root_leaves[0..i],
            spec.deposit_contract_tree_depth as usize,
        );

        let (_, mut proof) = tree.generate_proof(i - 1, spec.deposit_contract_tree_depth as usize);
        proof.push(Hash256::from_slice(&int_to_bytes32(i)));

        assert_eq!(
            proof.len(),
            spec.deposit_contract_tree_depth as usize + 1,
            "Deposit proof should be correct len"
        );

        proofs.push(proof);
    }

    let deposits = datas
        .into_par_iter()
        .zip(proofs.into_par_iter())
        .map(|(data, proof)| (data, proof.into()))
        .map(|(data, proof)| Deposit { proof, data })
        .collect::<Vec<_>>();

    let mut state =
        initialize_beacon_state_from_eth1(eth1_block_hash, eth1_timestamp, deposits, spec)
            .map_err(|e| format!("Unable to initialize genesis state: {:?}", e))?;

    state.genesis_time = genesis_time;

    // Invalid all the caches after all the manual state surgery.
    state.drop_all_caches();

    Ok(state)
}

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: usize) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}

/// Returns the system time, mod 30 minutes.
///
/// Used for easily creating testnets.
fn recent_genesis_time(minutes: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs_after_last_period = now.checked_rem(minutes * 60).unwrap_or(0);
    now - secs_after_last_period
}

/// An empty struct used to "witness" all the `BeaconChainTypes` traits. It has no user-facing
/// functionality and only exists to satisfy the type system.
struct Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>(
    PhantomData<(
        TStore,
        TSlotClock,
        TLmdGhost,
        TEth1Backend,
        TEthSpec,
        TEventHandler,
    )>,
);

impl<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler> BeaconChainTypes
    for Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    type Store = TStore;
    type SlotClock = TSlotClock;
    type LmdGhost = TLmdGhost;
    type Eth1Chain = TEth1Backend;
    type EthSpec = TEthSpec;
    type EventHandler = TEventHandler;
}

#[cfg(test)]
mod test {
    use super::*;
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::time::Duration;
    use store::MemoryStore;
    use types::{test_utils::generate_deterministic_keypairs, EthSpec, MinimalEthSpec, Slot};

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

        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(store.clone())
            .empty_op_pool()
            .initialize_state(&BeaconChainStartMethod::Generated {
                validator_count,
                genesis_time,
            })
            .expect("should build state using recent genesis")
            .interop_eth1_backend()
            .null_event_handler()
            .testing_slot_clock(Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .empty_reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
            .build()
            .expect("should build");

        let head = chain.head();
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
