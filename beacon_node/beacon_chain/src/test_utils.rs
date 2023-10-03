use crate::observed_operations::ObservationOutcome;
pub use crate::persisted_beacon_chain::PersistedBeaconChain;
pub use crate::{
    beacon_chain::{BEACON_CHAIN_DB_KEY, ETH1_CACHE_DB_KEY, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY},
    migrate::MigratorConfig,
    sync_committee_verification::Error as SyncCommitteeError,
    validator_monitor::{ValidatorMonitor, ValidatorMonitorConfig},
    BeaconChainError, NotifyExecutionLayer, ProduceBlockVerification,
};
use crate::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::CachingEth1Backend,
    BeaconChain, BeaconChainTypes, BlockError, ChainConfig, ServerSentEventHandler,
    StateSkipConfig,
};
use bls::get_withdrawal_credentials;
use execution_layer::{
    auth::JwtKey,
    test_utils::{
        ExecutionBlockGenerator, MockExecutionLayer, TestingBuilder, DEFAULT_JWT_SECRET,
        DEFAULT_TERMINAL_BLOCK,
    },
    ExecutionLayer,
};
use futures::channel::mpsc::Receiver;
pub use genesis::{interop_genesis_state_with_eth1, DEFAULT_ETH1_BLOCK_HASH};
use int_to_bytes::int_to_bytes32;
use merkle_proof::MerkleTree;
use operation_pool::ReceivedPreCapella;
use parking_lot::Mutex;
use parking_lot::RwLockWriteGuard;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use rayon::prelude::*;
use sensitive_url::SensitiveUrl;
use slog::Logger;
use slot_clock::{SlotClock, TestingSlotClock};
use state_processing::per_block_processing::compute_timestamp_at_slot;
use state_processing::{
    state_advance::{complete_state_advance, partial_state_advance},
    StateProcessingStrategy,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use store::{config::StoreConfig, HotColdDB, ItemStore, LevelDB, MemoryStore};
use task_executor::{test_utils::TestRuntime, ShutdownReason};
use tree_hash::TreeHash;
use types::sync_selection_proof::SyncSelectionProof;
pub use types::test_utils::generate_deterministic_keypairs;
use types::{typenum::U4294967296, *};

// 4th September 2019
pub const HARNESS_GENESIS_TIME: u64 = 1_567_552_690;
// Environment variable to read if `fork_from_env` feature is enabled.
const FORK_NAME_ENV_VAR: &str = "FORK_NAME";

// Default target aggregators to set during testing, this ensures an aggregator at each slot.
//
// You should mutate the `ChainSpec` prior to initialising the harness if you would like to use
// a different value.
pub const DEFAULT_TARGET_AGGREGATORS: u64 = u64::MAX;

pub type BaseHarnessType<TEthSpec, THotStore, TColdStore> =
    Witness<TestingSlotClock, CachingEth1Backend<TEthSpec>, TEthSpec, THotStore, TColdStore>;

pub type DiskHarnessType<E> = BaseHarnessType<E, LevelDB<E>, LevelDB<E>>;
pub type EphemeralHarnessType<E> = BaseHarnessType<E, MemoryStore<E>, MemoryStore<E>>;

pub type BoxedMutator<E, Hot, Cold> = Box<
    dyn FnOnce(
        BeaconChainBuilder<BaseHarnessType<E, Hot, Cold>>,
    ) -> BeaconChainBuilder<BaseHarnessType<E, Hot, Cold>>,
>;

pub type AddBlocksResult<E> = (
    HashMap<Slot, SignedBeaconBlockHash>,
    HashMap<Slot, BeaconStateHash>,
    SignedBeaconBlockHash,
    BeaconState<E>,
);

/// Indicates how the `BeaconChainHarness` should produce blocks.
#[derive(Clone, Copy, Debug)]
pub enum BlockStrategy {
    /// Produce blocks upon the canonical head (normal case).
    OnCanonicalHead,
    /// Ignore the canonical head and produce blocks upon the block at the given slot.
    ///
    /// Useful for simulating forks.
    ForkCanonicalChainAt {
        /// The slot of the parent of the first block produced.
        previous_slot: Slot,
        /// The slot of the first block produced (must be higher than `previous_slot`.
        first_slot: Slot,
    },
}

/// Indicates how the `BeaconChainHarness` should produce attestations.
#[derive(Clone, Debug)]
pub enum AttestationStrategy {
    /// All validators attest to whichever block the `BeaconChainHarness` has produced.
    AllValidators,
    /// Only the given validators should attest. All others should fail to produce attestations.
    SomeValidators(Vec<usize>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncCommitteeStrategy {
    /// All sync committee validators sign.
    AllValidators,
    /// No validators sign.
    NoValidators,
}

/// Indicates whether the `BeaconChainHarness` should use the `state.current_sync_committee` or
/// `state.next_sync_committee` when creating sync messages or contributions.
#[derive(Clone, Debug)]
pub enum RelativeSyncCommittee {
    Current,
    Next,
}

fn make_rng() -> Mutex<StdRng> {
    // Nondeterminism in tests is a highly undesirable thing.  Seed the RNG to some arbitrary
    // but fixed value for reproducibility.
    Mutex::new(StdRng::seed_from_u64(0x0DDB1A5E5BAD5EEDu64))
}

/// Return a `ChainSpec` suitable for test usage.
///
/// If the `fork_from_env` feature is enabled, read the fork to use from the FORK_NAME environment
/// variable. Otherwise use the default spec.
pub fn test_spec<E: EthSpec>() -> ChainSpec {
    let mut spec = if cfg!(feature = "fork_from_env") {
        let fork_name = std::env::var(FORK_NAME_ENV_VAR).unwrap_or_else(|e| {
            panic!(
                "{} env var must be defined when using fork_from_env: {:?}",
                FORK_NAME_ENV_VAR, e
            )
        });
        let fork = ForkName::from_str(fork_name.as_str()).unwrap();
        fork.make_genesis_spec(E::default_spec())
    } else {
        E::default_spec()
    };

    // Set target aggregators to a high value by default.
    spec.target_aggregators_per_committee = DEFAULT_TARGET_AGGREGATORS;
    spec
}

pub struct Builder<T: BeaconChainTypes> {
    eth_spec_instance: T::EthSpec,
    spec: Option<ChainSpec>,
    validator_keypairs: Option<Vec<Keypair>>,
    withdrawal_keypairs: Vec<Option<Keypair>>,
    chain_config: Option<ChainConfig>,
    store_config: Option<StoreConfig>,
    #[allow(clippy::type_complexity)]
    store: Option<Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>>,
    initial_mutator: Option<BoxedMutator<T::EthSpec, T::HotStore, T::ColdStore>>,
    store_mutator: Option<BoxedMutator<T::EthSpec, T::HotStore, T::ColdStore>>,
    execution_layer: Option<ExecutionLayer<T::EthSpec>>,
    mock_execution_layer: Option<MockExecutionLayer<T::EthSpec>>,
    mock_builder: Option<TestingBuilder<T::EthSpec>>,
    testing_slot_clock: Option<TestingSlotClock>,
    validator_monitor_config: Option<ValidatorMonitorConfig>,
    runtime: TestRuntime,
    log: Logger,
}

impl<E: EthSpec> Builder<EphemeralHarnessType<E>> {
    pub fn fresh_ephemeral_store(mut self) -> Self {
        let spec = self.spec.as_ref().expect("cannot build without spec");
        let validator_keypairs = self
            .validator_keypairs
            .clone()
            .expect("cannot build without validator keypairs");

        let store = Arc::new(
            HotColdDB::open_ephemeral(
                self.store_config.clone().unwrap_or_default(),
                spec.clone(),
                self.log.clone(),
            )
            .unwrap(),
        );
        let mutator = move |builder: BeaconChainBuilder<_>| {
            let genesis_state = interop_genesis_state_with_eth1::<E>(
                &validator_keypairs,
                HARNESS_GENESIS_TIME,
                Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
                None,
                builder.get_spec(),
            )
            .expect("should generate interop state");
            builder
                .genesis_state(genesis_state)
                .expect("should build state using recent genesis")
        };
        self.store = Some(store);
        self.store_mutator(Box::new(mutator))
    }

    /// Create a new ephemeral store that uses the specified `genesis_state`.
    pub fn genesis_state_ephemeral_store(mut self, genesis_state: BeaconState<E>) -> Self {
        let spec = self.spec.as_ref().expect("cannot build without spec");

        let store = Arc::new(
            HotColdDB::open_ephemeral(
                self.store_config.clone().unwrap_or_default(),
                spec.clone(),
                self.log.clone(),
            )
            .unwrap(),
        );
        let mutator = move |builder: BeaconChainBuilder<_>| {
            builder
                .genesis_state(genesis_state)
                .expect("should build state using recent genesis")
        };
        self.store = Some(store);
        self.store_mutator(Box::new(mutator))
    }

    /// Manually restore from a given `MemoryStore`.
    pub fn resumed_ephemeral_store(
        mut self,
        store: Arc<HotColdDB<E, MemoryStore<E>, MemoryStore<E>>>,
    ) -> Self {
        let mutator = move |builder: BeaconChainBuilder<_>| {
            builder
                .resume_from_db()
                .expect("should resume from database")
        };
        self.store = Some(store);
        self.store_mutator(Box::new(mutator))
    }
}

impl<E: EthSpec> Builder<DiskHarnessType<E>> {
    /// Disk store, start from genesis.
    pub fn fresh_disk_store(mut self, store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>) -> Self {
        let validator_keypairs = self
            .validator_keypairs
            .clone()
            .expect("cannot build without validator keypairs");

        let mutator = move |builder: BeaconChainBuilder<_>| {
            let genesis_state = interop_genesis_state_with_eth1::<E>(
                &validator_keypairs,
                HARNESS_GENESIS_TIME,
                Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
                None,
                builder.get_spec(),
            )
            .expect("should generate interop state");
            builder
                .genesis_state(genesis_state)
                .expect("should build state using recent genesis")
        };
        self.store = Some(store);
        self.store_mutator(Box::new(mutator))
    }

    /// Disk store, resume.
    pub fn resumed_disk_store(mut self, store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>) -> Self {
        let mutator = move |builder: BeaconChainBuilder<_>| {
            builder
                .resume_from_db()
                .expect("should resume from database")
        };
        self.store = Some(store);
        self.store_mutator(Box::new(mutator))
    }
}

impl<E, Hot, Cold> Builder<BaseHarnessType<E, Hot, Cold>>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    pub fn new(eth_spec_instance: E) -> Self {
        let runtime = TestRuntime::default();
        let log = runtime.log.clone();

        Self {
            eth_spec_instance,
            spec: None,
            validator_keypairs: None,
            withdrawal_keypairs: vec![],
            chain_config: None,
            store_config: None,
            store: None,
            initial_mutator: None,
            store_mutator: None,
            execution_layer: None,
            mock_execution_layer: None,
            mock_builder: None,
            testing_slot_clock: None,
            validator_monitor_config: None,
            runtime,
            log,
        }
    }

    pub fn deterministic_keypairs(self, num_keypairs: usize) -> Self {
        self.keypairs(types::test_utils::generate_deterministic_keypairs(
            num_keypairs,
        ))
    }

    pub fn keypairs(mut self, validator_keypairs: Vec<Keypair>) -> Self {
        self.validator_keypairs = Some(validator_keypairs);
        self
    }

    /// Initializes the BLS withdrawal keypairs for `num_keypairs` validators to
    /// the "determistic" values, regardless of wether or not the validator has
    /// a BLS or execution address in the genesis deposits.
    ///
    /// This aligns with the withdrawal commitments used in the "interop"
    /// genesis states.
    pub fn deterministic_withdrawal_keypairs(self, num_keypairs: usize) -> Self {
        self.withdrawal_keypairs(
            types::test_utils::generate_deterministic_keypairs(num_keypairs)
                .into_iter()
                .map(Option::Some)
                .collect(),
        )
    }

    pub fn withdrawal_keypairs(mut self, withdrawal_keypairs: Vec<Option<Keypair>>) -> Self {
        self.withdrawal_keypairs = withdrawal_keypairs;
        self
    }

    pub fn default_spec(self) -> Self {
        self.spec_or_default(None)
    }

    pub fn spec(self, spec: ChainSpec) -> Self {
        self.spec_or_default(Some(spec))
    }

    pub fn spec_or_default(mut self, spec: Option<ChainSpec>) -> Self {
        self.spec = Some(spec.unwrap_or_else(test_spec::<E>));
        self
    }

    pub fn logger(mut self, log: Logger) -> Self {
        self.log = log.clone();
        self.runtime.set_logger(log);
        self
    }

    /// This mutator will be run before the `store_mutator`.
    pub fn initial_mutator(mut self, mutator: BoxedMutator<E, Hot, Cold>) -> Self {
        assert!(
            self.initial_mutator.is_none(),
            "initial mutator already set"
        );
        self.initial_mutator = Some(mutator);
        self
    }

    /// This mutator will be run after the `initial_mutator`.
    pub fn store_mutator(mut self, mutator: BoxedMutator<E, Hot, Cold>) -> Self {
        assert!(self.store_mutator.is_none(), "store mutator already set");
        self.store_mutator = Some(mutator);
        self
    }

    pub fn validator_monitor_config(
        mut self,
        validator_monitor_config: ValidatorMonitorConfig,
    ) -> Self {
        self.validator_monitor_config = Some(validator_monitor_config);
        self
    }

    /// Purposefully replace the `store_mutator`.
    pub fn override_store_mutator(mut self, mutator: BoxedMutator<E, Hot, Cold>) -> Self {
        assert!(self.store_mutator.is_some(), "store mutator not set");
        self.store_mutator = Some(mutator);
        self
    }

    pub fn chain_config(mut self, chain_config: ChainConfig) -> Self {
        self.chain_config = Some(chain_config);
        self
    }

    pub fn execution_layer(mut self, urls: &[&str]) -> Self {
        assert!(
            self.execution_layer.is_none(),
            "execution layer already defined"
        );

        let urls: Vec<SensitiveUrl> = urls
            .iter()
            .map(|s| SensitiveUrl::parse(s))
            .collect::<Result<_, _>>()
            .unwrap();

        let config = execution_layer::Config {
            execution_endpoints: urls,
            secret_files: vec![],
            suggested_fee_recipient: Some(Address::repeat_byte(42)),
            ..Default::default()
        };
        let execution_layer = ExecutionLayer::from_config(
            config,
            self.runtime.task_executor.clone(),
            self.log.clone(),
        )
        .unwrap();

        self.execution_layer = Some(execution_layer);
        self
    }

    pub fn recalculate_fork_times_with_genesis(mut self, genesis_time: u64) -> Self {
        let mock = self
            .mock_execution_layer
            .as_mut()
            .expect("must have mock execution layer to recalculate fork times");
        let spec = self
            .spec
            .clone()
            .expect("cannot recalculate fork times without spec");
        mock.server.execution_block_generator().shanghai_time =
            spec.capella_fork_epoch.map(|epoch| {
                genesis_time + spec.seconds_per_slot * E::slots_per_epoch() * epoch.as_u64()
            });

        self
    }

    pub fn mock_execution_layer(mut self) -> Self {
        let spec = self.spec.clone().expect("cannot build without spec");
        let shanghai_time = spec.capella_fork_epoch.map(|epoch| {
            HARNESS_GENESIS_TIME + spec.seconds_per_slot * E::slots_per_epoch() * epoch.as_u64()
        });
        let mock = MockExecutionLayer::new(
            self.runtime.task_executor.clone(),
            DEFAULT_TERMINAL_BLOCK,
            shanghai_time,
            None,
            Some(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap()),
            spec,
            None,
        );
        self.execution_layer = Some(mock.el.clone());
        self.mock_execution_layer = Some(mock);
        self
    }

    pub fn mock_execution_layer_with_builder(
        mut self,
        beacon_url: SensitiveUrl,
        builder_threshold: Option<u128>,
    ) -> Self {
        // Get a random unused port
        let port = unused_port::unused_tcp4_port().unwrap();
        let builder_url = SensitiveUrl::parse(format!("http://127.0.0.1:{port}").as_str()).unwrap();

        let spec = self.spec.clone().expect("cannot build without spec");
        let shanghai_time = spec.capella_fork_epoch.map(|epoch| {
            HARNESS_GENESIS_TIME + spec.seconds_per_slot * E::slots_per_epoch() * epoch.as_u64()
        });
        let mock_el = MockExecutionLayer::new(
            self.runtime.task_executor.clone(),
            DEFAULT_TERMINAL_BLOCK,
            shanghai_time,
            builder_threshold,
            Some(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap()),
            spec.clone(),
            Some(builder_url.clone()),
        )
        .move_to_terminal_block();

        let mock_el_url = SensitiveUrl::parse(mock_el.server.url().as_str()).unwrap();

        self.mock_builder = Some(TestingBuilder::new(
            mock_el_url,
            builder_url,
            beacon_url,
            spec,
            self.runtime.task_executor.clone(),
        ));
        self.execution_layer = Some(mock_el.el.clone());
        self.mock_execution_layer = Some(mock_el);

        self
    }

    /// Instruct the mock execution engine to always return a "valid" response to any payload it is
    /// asked to execute.
    pub fn mock_execution_layer_all_payloads_valid(self) -> Self {
        self.mock_execution_layer
            .as_ref()
            .expect("requires mock execution layer")
            .server
            .all_payloads_valid();
        self
    }

    pub fn testing_slot_clock(mut self, slot_clock: TestingSlotClock) -> Self {
        self.testing_slot_clock = Some(slot_clock);
        self
    }

    pub fn build(self) -> BeaconChainHarness<BaseHarnessType<E, Hot, Cold>> {
        let (shutdown_tx, shutdown_receiver) = futures::channel::mpsc::channel(1);

        let log = self.log;
        let spec = self.spec.expect("cannot build without spec");
        let seconds_per_slot = spec.seconds_per_slot;
        let validator_keypairs = self
            .validator_keypairs
            .expect("cannot build without validator keypairs");

        let validator_monitor_config = self.validator_monitor_config.unwrap_or_default();

        let chain_config = self.chain_config.unwrap_or_default();
        let mut builder = BeaconChainBuilder::new(self.eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec)
            .store(self.store.expect("cannot build without store"))
            .store_migrator_config(
                MigratorConfig::default()
                    .blocking()
                    .epochs_per_migration(chain_config.epochs_per_migration),
            )
            .task_executor(self.runtime.task_executor.clone())
            .execution_layer(self.execution_layer)
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .shutdown_sender(shutdown_tx)
            .chain_config(chain_config)
            .event_handler(Some(ServerSentEventHandler::new_with_capacity(
                log.clone(),
                5,
            )))
            .validator_monitor_config(validator_monitor_config);

        builder = if let Some(mutator) = self.initial_mutator {
            mutator(builder)
        } else {
            builder
        };

        builder = if let Some(mutator) = self.store_mutator {
            mutator(builder)
        } else {
            builder
        };

        // Initialize the slot clock only if it hasn't already been initialized.
        builder = if let Some(testing_slot_clock) = self.testing_slot_clock {
            builder.slot_clock(testing_slot_clock)
        } else if builder.get_slot_clock().is_none() {
            builder
                .testing_slot_clock(Duration::from_secs(seconds_per_slot))
                .expect("should configure testing slot clock")
        } else {
            builder
        };

        let chain = builder.build().expect("should build");

        BeaconChainHarness {
            spec: chain.spec.clone(),
            chain: Arc::new(chain),
            validator_keypairs,
            withdrawal_keypairs: self.withdrawal_keypairs,
            shutdown_receiver: Arc::new(Mutex::new(shutdown_receiver)),
            runtime: self.runtime,
            mock_execution_layer: self.mock_execution_layer,
            mock_builder: self.mock_builder.map(Arc::new),
            rng: make_rng(),
        }
    }
}

/// A testing harness which can instantiate a `BeaconChain` and populate it with blocks and
/// attestations.
///
/// Used for testing.
pub struct BeaconChainHarness<T: BeaconChainTypes> {
    pub validator_keypairs: Vec<Keypair>,
    /// Optional BLS withdrawal keys for each validator.
    ///
    /// If a validator index is missing from this vec or their entry is `None` then either
    /// no BLS withdrawal key was set for them (they had an address from genesis) or the test
    /// initializer neglected to set this field.
    pub withdrawal_keypairs: Vec<Option<Keypair>>,

    pub chain: Arc<BeaconChain<T>>,
    pub spec: ChainSpec,
    pub shutdown_receiver: Arc<Mutex<Receiver<ShutdownReason>>>,
    pub runtime: TestRuntime,

    pub mock_execution_layer: Option<MockExecutionLayer<T::EthSpec>>,
    pub mock_builder: Option<Arc<TestingBuilder<T::EthSpec>>>,

    pub rng: Mutex<StdRng>,
}

pub type CommitteeAttestations<E> = Vec<(Attestation<E>, SubnetId)>;
pub type HarnessAttestations<E> =
    Vec<(CommitteeAttestations<E>, Option<SignedAggregateAndProof<E>>)>;

pub type HarnessSyncContributions<E> = Vec<(
    Vec<(SyncCommitteeMessage, usize)>,
    Option<SignedContributionAndProof<E>>,
)>;

impl<E, Hot, Cold> BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    pub fn builder(eth_spec_instance: E) -> Builder<BaseHarnessType<E, Hot, Cold>> {
        Builder::new(eth_spec_instance)
    }

    pub fn logger(&self) -> &slog::Logger {
        &self.chain.log
    }

    pub fn execution_block_generator(&self) -> RwLockWriteGuard<'_, ExecutionBlockGenerator<E>> {
        self.mock_execution_layer
            .as_ref()
            .expect("harness was not built with mock execution layer")
            .server
            .execution_block_generator()
    }

    pub fn get_all_validators(&self) -> Vec<usize> {
        (0..self.validator_keypairs.len()).collect()
    }

    pub fn slots_per_epoch(&self) -> u64 {
        E::slots_per_epoch()
    }

    pub fn epoch_start_slot(&self, epoch: u64) -> u64 {
        let epoch = Epoch::new(epoch);
        epoch.start_slot(E::slots_per_epoch()).into()
    }

    pub fn shutdown_reasons(&self) -> Vec<ShutdownReason> {
        let mutex = self.shutdown_receiver.clone();
        let mut receiver = mutex.lock();
        std::iter::from_fn(move || match receiver.try_next() {
            Ok(Some(s)) => Some(s),
            Ok(None) => panic!("shutdown sender dropped"),
            Err(_) => None,
        })
        .collect()
    }

    pub fn get_current_state(&self) -> BeaconState<E> {
        self.chain.head_beacon_state_cloned()
    }

    pub fn get_timestamp_at_slot(&self) -> u64 {
        let state = self.get_current_state();
        compute_timestamp_at_slot(&state, state.slot(), &self.spec).unwrap()
    }

    pub fn get_current_state_and_root(&self) -> (BeaconState<E>, Hash256) {
        let head = self.chain.head_snapshot();
        let state_root = head.beacon_state_root();
        (
            head.beacon_state.clone_with_only_committee_caches(),
            state_root,
        )
    }

    pub fn head_slot(&self) -> Slot {
        self.chain.canonical_head.cached_head().head_slot()
    }

    pub fn head_block_root(&self) -> Hash256 {
        self.chain.canonical_head.cached_head().head_block_root()
    }

    pub fn finalized_checkpoint(&self) -> Checkpoint {
        self.chain
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
    }

    pub fn justified_checkpoint(&self) -> Checkpoint {
        self.chain
            .canonical_head
            .cached_head()
            .justified_checkpoint()
    }

    pub fn get_current_slot(&self) -> Slot {
        self.chain.slot().unwrap()
    }

    pub fn get_block(
        &self,
        block_hash: SignedBeaconBlockHash,
    ) -> Option<SignedBeaconBlock<E, BlindedPayload<E>>> {
        self.chain.get_blinded_block(&block_hash.into()).unwrap()
    }

    pub fn block_exists(&self, block_hash: SignedBeaconBlockHash) -> bool {
        self.get_block(block_hash).is_some()
    }

    pub fn get_hot_state(&self, state_hash: BeaconStateHash) -> Option<BeaconState<E>> {
        self.chain
            .store
            .load_hot_state(&state_hash.into(), StateProcessingStrategy::Accurate)
            .unwrap()
    }

    pub fn get_cold_state(&self, state_hash: BeaconStateHash) -> Option<BeaconState<E>> {
        self.chain
            .store
            .load_cold_state(&state_hash.into())
            .unwrap()
    }

    pub fn hot_state_exists(&self, state_hash: BeaconStateHash) -> bool {
        self.get_hot_state(state_hash).is_some()
    }

    pub fn cold_state_exists(&self, state_hash: BeaconStateHash) -> bool {
        self.get_cold_state(state_hash).is_some()
    }

    pub fn is_skipped_slot(&self, state: &BeaconState<E>, slot: Slot) -> bool {
        state.get_block_root(slot).unwrap() == state.get_block_root(slot - 1).unwrap()
    }

    pub async fn make_blinded_block(
        &self,
        state: BeaconState<E>,
        slot: Slot,
    ) -> (SignedBlindedBeaconBlock<E>, BeaconState<E>) {
        let (unblinded, new_state) = self.make_block(state, slot).await;
        (unblinded.into(), new_state)
    }

    /// Returns a newly created block, signed by the proposer for the given slot.
    pub async fn make_block(
        &self,
        mut state: BeaconState<E>,
        slot: Slot,
    ) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        assert_ne!(slot, 0, "can't produce a block at slot 0");
        assert!(slot >= state.slot());

        complete_state_advance(&mut state, None, slot, &self.spec)
            .expect("should be able to advance state to slot");

        state.build_caches(&self.spec).expect("should build caches");

        let proposer_index = state.get_beacon_proposer_index(slot, &self.spec).unwrap();

        // If we produce two blocks for the same slot, they hash up to the same value and
        // BeaconChain errors out with `BlockIsAlreadyKnown`.  Vary the graffiti so that we produce
        // different blocks each time.
        let graffiti = Graffiti::from(self.rng.lock().gen::<[u8; 32]>());

        let randao_reveal = self.sign_randao_reveal(&state, proposer_index, slot);

        let (block, state) = self
            .chain
            .produce_block_on_state(
                state,
                None,
                slot,
                randao_reveal,
                Some(graffiti),
                ProduceBlockVerification::VerifyRandao,
            )
            .await
            .unwrap();

        let signed_block = block.sign(
            &self.validator_keypairs[proposer_index].sk,
            &state.fork(),
            state.genesis_validators_root(),
            &self.spec,
        );

        (signed_block, state)
    }

    /// Useful for the `per_block_processing` tests. Creates a block, and returns the state after
    /// caches are built but before the generated block is processed.
    pub async fn make_block_return_pre_state(
        &self,
        mut state: BeaconState<E>,
        slot: Slot,
    ) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        assert_ne!(slot, 0, "can't produce a block at slot 0");
        assert!(slot >= state.slot());

        complete_state_advance(&mut state, None, slot, &self.spec)
            .expect("should be able to advance state to slot");

        state.build_caches(&self.spec).expect("should build caches");

        let proposer_index = state.get_beacon_proposer_index(slot, &self.spec).unwrap();

        // If we produce two blocks for the same slot, they hash up to the same value and
        // BeaconChain errors out with `BlockIsAlreadyKnown`.  Vary the graffiti so that we produce
        // different blocks each time.
        let graffiti = Graffiti::from(self.rng.lock().gen::<[u8; 32]>());

        let randao_reveal = self.sign_randao_reveal(&state, proposer_index, slot);

        let pre_state = state.clone();

        let (block, state) = self
            .chain
            .produce_block_on_state(
                state,
                None,
                slot,
                randao_reveal,
                Some(graffiti),
                ProduceBlockVerification::VerifyRandao,
            )
            .await
            .unwrap();

        let signed_block = block.sign(
            &self.validator_keypairs[proposer_index].sk,
            &state.fork(),
            state.genesis_validators_root(),
            &self.spec,
        );

        (signed_block, pre_state)
    }

    /// Create a randao reveal for a block at `slot`.
    pub fn sign_randao_reveal(
        &self,
        state: &BeaconState<E>,
        proposer_index: usize,
        slot: Slot,
    ) -> Signature {
        let epoch = slot.epoch(E::slots_per_epoch());
        let domain = self.spec.get_domain(
            epoch,
            Domain::Randao,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let message = epoch.signing_root(domain);
        let sk = &self.validator_keypairs[proposer_index].sk;
        sk.sign(message)
    }

    /// Sign a beacon block using the proposer's key.
    pub fn sign_beacon_block(
        &self,
        block: BeaconBlock<E>,
        state: &BeaconState<E>,
    ) -> SignedBeaconBlock<E> {
        let proposer_index = block.proposer_index() as usize;
        block.sign(
            &self.validator_keypairs[proposer_index].sk,
            &state.fork(),
            state.genesis_validators_root(),
            &self.spec,
        )
    }

    /// Produces an "unaggregated" attestation for the given `slot` and `index` that attests to
    /// `beacon_block_root`. The provided `state` should match the `block.state_root` for the
    /// `block` identified by `beacon_block_root`.
    ///
    /// The attestation doesn't _really_ have anything about it that makes it unaggregated per say,
    /// however this function is only required in the context of forming an unaggregated
    /// attestation. It would be an (undetectable) violation of the protocol to create a
    /// `SignedAggregateAndProof` based upon the output of this function.
    ///
    /// This function will produce attestations to optimistic blocks, which is against the
    /// specification but useful during testing.
    pub fn produce_unaggregated_attestation_for_block(
        &self,
        slot: Slot,
        index: CommitteeIndex,
        beacon_block_root: Hash256,
        mut state: Cow<BeaconState<E>>,
        state_root: Hash256,
    ) -> Result<Attestation<E>, BeaconChainError> {
        let epoch = slot.epoch(E::slots_per_epoch());

        if state.slot() > slot {
            return Err(BeaconChainError::CannotAttestToFutureState);
        } else if state.current_epoch() < epoch {
            let mut_state = state.to_mut();
            // Only perform a "partial" state advance since we do not require the state roots to be
            // accurate.
            partial_state_advance(
                mut_state,
                Some(state_root),
                epoch.start_slot(E::slots_per_epoch()),
                &self.spec,
            )?;
            mut_state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;
        }

        let committee_len = state.get_beacon_committee(slot, index)?.committee.len();

        let target_slot = epoch.start_slot(E::slots_per_epoch());
        let target_root = if state.slot() <= target_slot {
            beacon_block_root
        } else {
            *state.get_block_root(target_slot)?
        };

        Ok(Attestation {
            aggregation_bits: BitList::with_capacity(committee_len)?,
            data: AttestationData {
                slot,
                index,
                beacon_block_root,
                source: state.current_justified_checkpoint(),
                target: Checkpoint {
                    epoch,
                    root: target_root,
                },
            },
            signature: AggregateSignature::empty(),
        })
    }

    /// A list of attestations for each committee for the given slot.
    ///
    /// The first layer of the Vec is organised per committee. For example, if the return value is
    /// called `all_attestations`, then all attestations in `all_attestations[0]` will be for
    /// committee 0, whilst all in `all_attestations[1]` will be for committee 1.
    pub fn make_unaggregated_attestations(
        &self,
        attesting_validators: &[usize],
        state: &BeaconState<E>,
        state_root: Hash256,
        head_block_root: SignedBeaconBlockHash,
        attestation_slot: Slot,
    ) -> Vec<CommitteeAttestations<E>> {
        let fork = self
            .spec
            .fork_at_epoch(attestation_slot.epoch(E::slots_per_epoch()));
        self.make_unaggregated_attestations_with_opts(
            attesting_validators,
            state,
            state_root,
            head_block_root,
            attestation_slot,
            MakeAttestationOptions { limit: None, fork },
        )
        .0
    }

    pub fn make_unaggregated_attestations_with_opts(
        &self,
        attesting_validators: &[usize],
        state: &BeaconState<E>,
        state_root: Hash256,
        head_block_root: SignedBeaconBlockHash,
        attestation_slot: Slot,
        opts: MakeAttestationOptions,
    ) -> (Vec<CommitteeAttestations<E>>, Vec<usize>) {
        let MakeAttestationOptions { limit, fork } = opts;
        let committee_count = state.get_committee_count_at_slot(state.slot()).unwrap();
        let attesters = Mutex::new(vec![]);

        let attestations = state
            .get_beacon_committees_at_slot(attestation_slot)
            .expect("should get committees")
            .iter()
            .map(|bc| {
                bc.committee
                    .par_iter()
                    .enumerate()
                    .filter_map(|(i, validator_index)| {
                        if !attesting_validators.contains(validator_index) {
                            return None;
                        }

                        let mut attesters = attesters.lock();
                        if let Some(limit) = limit {
                            if attesters.len() >= limit {
                                return None;
                            }
                        }
                        attesters.push(*validator_index);

                        let mut attestation = self
                            .produce_unaggregated_attestation_for_block(
                                attestation_slot,
                                bc.index,
                                head_block_root.into(),
                                Cow::Borrowed(state),
                                state_root,
                            )
                            .unwrap();

                        attestation.aggregation_bits.set(i, true).unwrap();

                        attestation.signature = {
                            let domain = self.spec.get_domain(
                                attestation.data.target.epoch,
                                Domain::BeaconAttester,
                                &fork,
                                state.genesis_validators_root(),
                            );

                            let message = attestation.data.signing_root(domain);

                            let mut agg_sig = AggregateSignature::infinity();

                            agg_sig.add_assign(
                                &self.validator_keypairs[*validator_index].sk.sign(message),
                            );

                            agg_sig
                        };

                        let subnet_id = SubnetId::compute_subnet_for_attestation_data::<E>(
                            &attestation.data,
                            committee_count,
                            &self.chain.spec,
                        )
                        .unwrap();

                        Some((attestation, subnet_id))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let attesters = attesters.into_inner();
        if let Some(limit) = limit {
            assert_eq!(
                limit,
                attesters.len(),
                "failed to generate `limit` attestations"
            );
        }
        (attestations, attesters)
    }

    /// A list of sync messages for the given state.
    pub fn make_sync_committee_messages(
        &self,
        state: &BeaconState<E>,
        head_block_root: Hash256,
        message_slot: Slot,
        relative_sync_committee: RelativeSyncCommittee,
    ) -> Vec<Vec<(SyncCommitteeMessage, usize)>> {
        let sync_committee: Arc<SyncCommittee<E>> = match relative_sync_committee {
            RelativeSyncCommittee::Current => state
                .current_sync_committee()
                .expect("should be called on altair beacon state")
                .clone(),
            RelativeSyncCommittee::Next => state
                .next_sync_committee()
                .expect("should be called on altair beacon state")
                .clone(),
        };
        let fork = self
            .spec
            .fork_at_epoch(message_slot.epoch(E::slots_per_epoch()));

        sync_committee
            .pubkeys
            .as_ref()
            .chunks(E::sync_subcommittee_size())
            .map(|subcommittee| {
                subcommittee
                    .iter()
                    .enumerate()
                    .map(|(subcommittee_position, pubkey)| {
                        let validator_index = self
                            .chain
                            .validator_index(pubkey)
                            .expect("should find validator index")
                            .expect("pubkey should exist in the beacon chain");

                        let sync_message = SyncCommitteeMessage::new::<E>(
                            message_slot,
                            head_block_root,
                            validator_index as u64,
                            &self.validator_keypairs[validator_index].sk,
                            &fork,
                            state.genesis_validators_root(),
                            &self.spec,
                        );

                        (sync_message, subcommittee_position)
                    })
                    .collect()
            })
            .collect()
    }

    /// A list of attestations for each committee for the given slot.
    ///
    /// The first layer of the Vec is organised per committee. For example, if the return value is
    /// called `all_attestations`, then all attestations in `all_attestations[0]` will be for
    /// committee 0, whilst all in `all_attestations[1]` will be for committee 1.
    pub fn get_unaggregated_attestations(
        &self,
        attestation_strategy: &AttestationStrategy,
        state: &BeaconState<E>,
        state_root: Hash256,
        head_block_root: Hash256,
        attestation_slot: Slot,
    ) -> Vec<Vec<(Attestation<E>, SubnetId)>> {
        let validators: Vec<usize> = match attestation_strategy {
            AttestationStrategy::AllValidators => self.get_all_validators(),
            AttestationStrategy::SomeValidators(vals) => vals.clone(),
        };
        self.make_unaggregated_attestations(
            &validators,
            state,
            state_root,
            head_block_root.into(),
            attestation_slot,
        )
    }

    pub fn make_attestations(
        &self,
        attesting_validators: &[usize],
        state: &BeaconState<E>,
        state_root: Hash256,
        block_hash: SignedBeaconBlockHash,
        slot: Slot,
    ) -> HarnessAttestations<E> {
        self.make_attestations_with_limit(
            attesting_validators,
            state,
            state_root,
            block_hash,
            slot,
            None,
        )
        .0
    }

    /// Produce exactly `limit` attestations.
    ///
    /// Return attestations and vec of validator indices that attested.
    pub fn make_attestations_with_limit(
        &self,
        attesting_validators: &[usize],
        state: &BeaconState<E>,
        state_root: Hash256,
        block_hash: SignedBeaconBlockHash,
        slot: Slot,
        limit: Option<usize>,
    ) -> (HarnessAttestations<E>, Vec<usize>) {
        let fork = self.spec.fork_at_epoch(slot.epoch(E::slots_per_epoch()));
        self.make_attestations_with_opts(
            attesting_validators,
            state,
            state_root,
            block_hash,
            slot,
            MakeAttestationOptions { limit, fork },
        )
    }

    pub fn make_attestations_with_opts(
        &self,
        attesting_validators: &[usize],
        state: &BeaconState<E>,
        state_root: Hash256,
        block_hash: SignedBeaconBlockHash,
        slot: Slot,
        opts: MakeAttestationOptions,
    ) -> (HarnessAttestations<E>, Vec<usize>) {
        let MakeAttestationOptions { fork, .. } = opts;
        let (unaggregated_attestations, attesters) = self.make_unaggregated_attestations_with_opts(
            attesting_validators,
            state,
            state_root,
            block_hash,
            slot,
            opts,
        );

        let aggregated_attestations: Vec<Option<SignedAggregateAndProof<E>>> =
            unaggregated_attestations
                .iter()
                .map(|committee_attestations| {
                    // If there are any attestations in this committee, create an aggregate.
                    if let Some((attestation, _)) = committee_attestations.first() {
                        let bc = state
                            .get_beacon_committee(attestation.data.slot, attestation.data.index)
                            .unwrap();

                        // Find an aggregator if one exists. Return `None` if there are no
                        // aggregators.
                        let aggregator_index = bc
                            .committee
                            .iter()
                            .find(|&validator_index| {
                                if !attesters.contains(validator_index) {
                                    return false;
                                }

                                let selection_proof = SelectionProof::new::<E>(
                                    slot,
                                    &self.validator_keypairs[*validator_index].sk,
                                    &fork,
                                    state.genesis_validators_root(),
                                    &self.spec,
                                );

                                selection_proof
                                    .is_aggregator(bc.committee.len(), &self.spec)
                                    .unwrap_or(false)
                            })
                            .copied()?;

                        // If the chain is able to produce an aggregate, use that. Otherwise, build an
                        // aggregate locally.
                        let aggregate = self
                            .chain
                            .get_aggregated_attestation(&attestation.data)
                            .unwrap()
                            .unwrap_or_else(|| {
                                committee_attestations.iter().skip(1).fold(
                                    attestation.clone(),
                                    |mut agg, (att, _)| {
                                        agg.aggregate(att);
                                        agg
                                    },
                                )
                            });

                        let signed_aggregate = SignedAggregateAndProof::from_aggregate(
                            aggregator_index as u64,
                            aggregate,
                            None,
                            &self.validator_keypairs[aggregator_index].sk,
                            &fork,
                            state.genesis_validators_root(),
                            &self.spec,
                        );

                        Some(signed_aggregate)
                    } else {
                        None
                    }
                })
                .collect();

        (
            unaggregated_attestations
                .into_iter()
                .zip(aggregated_attestations)
                .collect(),
            attesters,
        )
    }

    pub fn make_sync_contributions(
        &self,
        state: &BeaconState<E>,
        block_hash: Hash256,
        slot: Slot,
        relative_sync_committee: RelativeSyncCommittee,
    ) -> HarnessSyncContributions<E> {
        let sync_messages =
            self.make_sync_committee_messages(state, block_hash, slot, relative_sync_committee);

        let sync_contributions: Vec<Option<SignedContributionAndProof<E>>> = sync_messages
            .iter()
            .enumerate()
            .map(|(subnet_id, committee_messages)| {
                // If there are any sync messages in this committee, create an aggregate.
                if let Some((sync_message, subcommittee_position)) = committee_messages.first() {
                    let sync_committee: Arc<SyncCommittee<E>> = state
                        .current_sync_committee()
                        .expect("should be called on altair beacon state")
                        .clone();

                    let aggregator_index = sync_committee
                        .get_subcommittee_pubkeys(subnet_id)
                        .unwrap()
                        .iter()
                        .find_map(|pubkey| {
                            let validator_index = self
                                .chain
                                .validator_index(pubkey)
                                .expect("should find validator index")
                                .expect("pubkey should exist in the beacon chain");

                            let selection_proof = SyncSelectionProof::new::<E>(
                                slot,
                                subnet_id as u64,
                                &self.validator_keypairs[validator_index].sk,
                                &state.fork(),
                                state.genesis_validators_root(),
                                &self.spec,
                            );

                            selection_proof
                                .is_aggregator::<E>()
                                .expect("should determine aggregator")
                                .then_some(validator_index)
                        })?;

                    let default = SyncCommitteeContribution::from_message(
                        sync_message,
                        subnet_id as u64,
                        *subcommittee_position,
                    )
                    .expect("should derive sync contribution");

                    let aggregate = committee_messages.iter().skip(1).fold(
                        default,
                        |mut agg, (sig, position)| {
                            let contribution = SyncCommitteeContribution::from_message(
                                sig,
                                subnet_id as u64,
                                *position,
                            )
                            .expect("should derive sync contribution");
                            agg.aggregate(&contribution);
                            agg
                        },
                    );

                    let signed_aggregate = SignedContributionAndProof::from_aggregate(
                        aggregator_index as u64,
                        aggregate,
                        None,
                        &self.validator_keypairs[aggregator_index].sk,
                        &state.fork(),
                        state.genesis_validators_root(),
                        &self.spec,
                    );

                    Some(signed_aggregate)
                } else {
                    None
                }
            })
            .collect();

        sync_messages.into_iter().zip(sync_contributions).collect()
    }

    pub fn make_attester_slashing(&self, validator_indices: Vec<u64>) -> AttesterSlashing<E> {
        self.make_attester_slashing_with_epochs(validator_indices, None, None, None, None)
    }

    pub fn make_attester_slashing_with_epochs(
        &self,
        validator_indices: Vec<u64>,
        source1: Option<Epoch>,
        target1: Option<Epoch>,
        source2: Option<Epoch>,
        target2: Option<Epoch>,
    ) -> AttesterSlashing<E> {
        let fork = self.chain.canonical_head.cached_head().head_fork();

        let mut attestation_1 = IndexedAttestation {
            attesting_indices: VariableList::new(validator_indices).unwrap(),
            data: AttestationData {
                slot: Slot::new(0),
                index: 0,
                beacon_block_root: Hash256::zero(),
                target: Checkpoint {
                    root: Hash256::zero(),
                    epoch: target1.unwrap_or(fork.epoch),
                },
                source: Checkpoint {
                    root: Hash256::zero(),
                    epoch: source1.unwrap_or(Epoch::new(0)),
                },
            },
            signature: AggregateSignature::infinity(),
        };

        let mut attestation_2 = attestation_1.clone();
        attestation_2.data.index += 1;
        attestation_2.data.source.epoch = source2.unwrap_or(Epoch::new(0));
        attestation_2.data.target.epoch = target2.unwrap_or(fork.epoch);

        for attestation in &mut [&mut attestation_1, &mut attestation_2] {
            for &i in &attestation.attesting_indices {
                let sk = &self.validator_keypairs[i as usize].sk;

                let genesis_validators_root = self.chain.genesis_validators_root;

                let domain = self.chain.spec.get_domain(
                    attestation.data.target.epoch,
                    Domain::BeaconAttester,
                    &fork,
                    genesis_validators_root,
                );
                let message = attestation.data.signing_root(domain);

                attestation.signature.add_assign(&sk.sign(message));
            }
        }

        AttesterSlashing {
            attestation_1,
            attestation_2,
        }
    }

    pub fn make_attester_slashing_different_indices(
        &self,
        validator_indices_1: Vec<u64>,
        validator_indices_2: Vec<u64>,
    ) -> AttesterSlashing<E> {
        let data = AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::zero(),
            target: Checkpoint {
                root: Hash256::zero(),
                epoch: Epoch::new(0),
            },
            source: Checkpoint {
                root: Hash256::zero(),
                epoch: Epoch::new(0),
            },
        };

        let mut attestation_1 = IndexedAttestation {
            attesting_indices: VariableList::new(validator_indices_1).unwrap(),
            data: data.clone(),
            signature: AggregateSignature::infinity(),
        };

        let mut attestation_2 = IndexedAttestation {
            attesting_indices: VariableList::new(validator_indices_2).unwrap(),
            data,
            signature: AggregateSignature::infinity(),
        };

        attestation_2.data.index += 1;

        let fork = self.chain.canonical_head.cached_head().head_fork();
        for attestation in &mut [&mut attestation_1, &mut attestation_2] {
            for &i in &attestation.attesting_indices {
                let sk = &self.validator_keypairs[i as usize].sk;

                let genesis_validators_root = self.chain.genesis_validators_root;

                let domain = self.chain.spec.get_domain(
                    attestation.data.target.epoch,
                    Domain::BeaconAttester,
                    &fork,
                    genesis_validators_root,
                );
                let message = attestation.data.signing_root(domain);

                attestation.signature.add_assign(&sk.sign(message));
            }
        }

        AttesterSlashing {
            attestation_1,
            attestation_2,
        }
    }

    pub fn make_proposer_slashing(&self, validator_index: u64) -> ProposerSlashing {
        self.make_proposer_slashing_at_slot(validator_index, None)
    }

    pub fn make_proposer_slashing_at_slot(
        &self,
        validator_index: u64,
        slot_override: Option<Slot>,
    ) -> ProposerSlashing {
        let mut block_header_1 = self.chain.head_beacon_block().message().block_header();
        block_header_1.proposer_index = validator_index;
        if let Some(slot) = slot_override {
            block_header_1.slot = slot;
        }

        let mut block_header_2 = block_header_1.clone();
        block_header_2.state_root = Hash256::zero();

        let sk = &self.validator_keypairs[validator_index as usize].sk;
        let fork = self.chain.canonical_head.cached_head().head_fork();
        let genesis_validators_root = self.chain.genesis_validators_root;

        let mut signed_block_headers = vec![block_header_1, block_header_2]
            .into_iter()
            .map(|block_header| {
                block_header.sign::<E>(sk, &fork, genesis_validators_root, &self.chain.spec)
            })
            .collect::<Vec<_>>();

        ProposerSlashing {
            signed_header_2: signed_block_headers.remove(1),
            signed_header_1: signed_block_headers.remove(0),
        }
    }

    pub fn make_voluntary_exit(&self, validator_index: u64, epoch: Epoch) -> SignedVoluntaryExit {
        let sk = &self.validator_keypairs[validator_index as usize].sk;
        let fork = self.chain.canonical_head.cached_head().head_fork();
        let genesis_validators_root = self.chain.genesis_validators_root;

        VoluntaryExit {
            epoch,
            validator_index,
        }
        .sign(sk, &fork, genesis_validators_root, &self.chain.spec)
    }

    pub fn add_proposer_slashing(&self, validator_index: u64) -> Result<(), String> {
        let propposer_slashing = self.make_proposer_slashing(validator_index);
        if let ObservationOutcome::New(verified_proposer_slashing) = self
            .chain
            .verify_proposer_slashing_for_gossip(propposer_slashing)
            .expect("should verify proposer slashing for gossip")
        {
            self.chain
                .import_proposer_slashing(verified_proposer_slashing);
            Ok(())
        } else {
            Err("should observe new proposer slashing".to_string())
        }
    }

    pub fn add_attester_slashing(&self, validator_indices: Vec<u64>) -> Result<(), String> {
        let attester_slashing = self.make_attester_slashing(validator_indices);
        if let ObservationOutcome::New(verified_attester_slashing) = self
            .chain
            .verify_attester_slashing_for_gossip(attester_slashing)
            .expect("should verify attester slashing for gossip")
        {
            self.chain
                .import_attester_slashing(verified_attester_slashing);
            Ok(())
        } else {
            Err("should observe new attester slashing".to_string())
        }
    }

    pub fn add_bls_to_execution_change(
        &self,
        validator_index: u64,
        address: Address,
    ) -> Result<(), String> {
        let signed_bls_change = self.make_bls_to_execution_change(validator_index, address);
        if let ObservationOutcome::New(verified_bls_change) = self
            .chain
            .verify_bls_to_execution_change_for_gossip(signed_bls_change)
            .expect("should verify BLS to execution change for gossip")
        {
            self.chain
                .import_bls_to_execution_change(verified_bls_change, ReceivedPreCapella::No)
                .then_some(())
                .ok_or("should import BLS to execution change to the op pool".to_string())
        } else {
            Err("should observe new BLS to execution change".to_string())
        }
    }

    pub fn make_bls_to_execution_change(
        &self,
        validator_index: u64,
        address: Address,
    ) -> SignedBlsToExecutionChange {
        let keypair = self.get_withdrawal_keypair(validator_index);
        self.make_bls_to_execution_change_with_keys(
            validator_index,
            address,
            &keypair.pk,
            &keypair.sk,
        )
    }

    pub fn make_bls_to_execution_change_with_keys(
        &self,
        validator_index: u64,
        address: Address,
        pubkey: &PublicKey,
        secret_key: &SecretKey,
    ) -> SignedBlsToExecutionChange {
        let genesis_validators_root = self.chain.genesis_validators_root;
        BlsToExecutionChange {
            validator_index,
            from_bls_pubkey: pubkey.compress(),
            to_execution_address: address,
        }
        .sign(secret_key, genesis_validators_root, &self.chain.spec)
    }

    pub fn get_withdrawal_keypair(&self, validator_index: u64) -> &Keypair {
        self.withdrawal_keypairs
            .get(validator_index as usize)
            .expect("BLS withdrawal key missing from harness")
            .as_ref()
            .expect("no withdrawal key for validator")
    }

    pub fn add_voluntary_exit(
        &self,
        block: &mut BeaconBlock<E>,
        validator_index: u64,
        epoch: Epoch,
    ) {
        let exit = self.make_voluntary_exit(validator_index, epoch);
        block.body_mut().voluntary_exits_mut().push(exit).unwrap();
    }

    /// Create a new block, apply `block_modifier` to it, sign it and return it.
    ///
    /// The state returned is a pre-block state at the same slot as the produced block.
    pub async fn make_block_with_modifier(
        &self,
        state: BeaconState<E>,
        slot: Slot,
        block_modifier: impl FnOnce(&mut BeaconBlock<E>),
    ) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        assert_ne!(slot, 0, "can't produce a block at slot 0");
        assert!(slot >= state.slot());

        let (block, state) = self.make_block_return_pre_state(state, slot).await;
        let (mut block, _) = block.deconstruct();

        block_modifier(&mut block);

        let proposer_index = state.get_beacon_proposer_index(slot, &self.spec).unwrap();

        let signed_block = block.sign(
            &self.validator_keypairs[proposer_index].sk,
            &state.fork(),
            state.genesis_validators_root(),
            &self.spec,
        );
        (signed_block, state)
    }

    pub fn make_deposits<'a>(
        &self,
        state: &'a mut BeaconState<E>,
        num_deposits: usize,
        invalid_pubkey: Option<PublicKeyBytes>,
        invalid_signature: Option<SignatureBytes>,
    ) -> (Vec<Deposit>, &'a mut BeaconState<E>) {
        let mut datas = vec![];

        for _ in 0..num_deposits {
            let keypair = Keypair::random();
            let pubkeybytes = PublicKeyBytes::from(keypair.pk.clone());

            let mut data = DepositData {
                pubkey: pubkeybytes,
                withdrawal_credentials: Hash256::from_slice(
                    &get_withdrawal_credentials(&keypair.pk, self.spec.bls_withdrawal_prefix_byte)
                        [..],
                ),
                amount: self.spec.min_deposit_amount,
                signature: SignatureBytes::empty(),
            };

            data.signature = data.create_signature(&keypair.sk, &self.spec);

            if let Some(invalid_pubkey) = invalid_pubkey {
                data.pubkey = invalid_pubkey;
            }
            if let Some(invalid_signature) = invalid_signature.clone() {
                data.signature = invalid_signature;
            }
            datas.push(data);
        }

        // Vector containing all leaves
        let leaves = datas
            .iter()
            .map(|data| data.tree_hash_root())
            .collect::<Vec<_>>();

        // Building a VarList from leaves
        let deposit_data_list = VariableList::<_, U4294967296>::from(leaves.clone());

        // Setting the deposit_root to be the tree_hash_root of the VarList
        state.eth1_data_mut().deposit_root = deposit_data_list.tree_hash_root();
        state.eth1_data_mut().deposit_count = num_deposits as u64;
        *state.eth1_deposit_index_mut() = 0;

        // Building the merkle tree used for generating proofs
        let tree = MerkleTree::create(&leaves[..], self.spec.deposit_contract_tree_depth as usize);

        // Building proofs
        let mut proofs = vec![];
        for i in 0..leaves.len() {
            let (_, mut proof) = tree
                .generate_proof(i, self.spec.deposit_contract_tree_depth as usize)
                .expect("should generate proof");
            proof.push(Hash256::from_slice(&int_to_bytes32(leaves.len() as u64)));
            proofs.push(proof);
        }

        // Building deposits
        let deposits = datas
            .into_par_iter()
            .zip(proofs.into_par_iter())
            .map(|(data, proof)| (data, proof.into()))
            .map(|(data, proof)| Deposit { proof, data })
            .collect::<Vec<_>>();

        // Pushing deposits to block body
        (deposits, state)
    }

    pub async fn process_block(
        &self,
        slot: Slot,
        block_root: Hash256,
        block: SignedBeaconBlock<E>,
    ) -> Result<SignedBeaconBlockHash, BlockError<E>> {
        self.set_current_slot(slot);
        let block_hash: SignedBeaconBlockHash = self
            .chain
            .process_block(
                block_root,
                Arc::new(block),
                NotifyExecutionLayer::Yes,
                || Ok(()),
            )
            .await?
            .into();
        self.chain.recompute_head_at_current_slot().await;
        Ok(block_hash)
    }

    pub async fn process_block_result(
        &self,
        block: SignedBeaconBlock<E>,
    ) -> Result<SignedBeaconBlockHash, BlockError<E>> {
        let block_hash: SignedBeaconBlockHash = self
            .chain
            .process_block(
                block.canonical_root(),
                Arc::new(block),
                NotifyExecutionLayer::Yes,
                || Ok(()),
            )
            .await?
            .into();
        self.chain.recompute_head_at_current_slot().await;
        Ok(block_hash)
    }

    pub fn process_attestations(&self, attestations: HarnessAttestations<E>) {
        let num_validators = self.validator_keypairs.len();
        let mut unaggregated = Vec::with_capacity(num_validators);
        // This is an over-allocation, but it should be fine. It won't be *that* memory hungry and
        // it's nice to have fast tests.
        let mut aggregated = Vec::with_capacity(num_validators);

        for (unaggregated_attestations, maybe_signed_aggregate) in attestations.iter() {
            for (attn, subnet) in unaggregated_attestations {
                unaggregated.push((attn, Some(*subnet)));
            }

            if let Some(a) = maybe_signed_aggregate {
                aggregated.push(a)
            }
        }

        for result in self
            .chain
            .batch_verify_unaggregated_attestations_for_gossip(unaggregated.into_iter())
            .unwrap()
        {
            let verified = result.unwrap();
            self.chain.add_to_naive_aggregation_pool(&verified).unwrap();
        }

        for result in self
            .chain
            .batch_verify_aggregated_attestations_for_gossip(aggregated.into_iter())
            .unwrap()
        {
            let verified = result.unwrap();
            self.chain
                .apply_attestation_to_fork_choice(&verified)
                .unwrap();
            self.chain.add_to_block_inclusion_pool(verified).unwrap();
        }
    }

    pub fn set_current_slot(&self, slot: Slot) {
        let current_slot = self.chain.slot().unwrap();
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let epoch = slot.epoch(E::slots_per_epoch());
        assert!(
            epoch >= current_epoch,
            "Jumping backwards to an earlier epoch isn't well defined. \
             Please generate test blocks epoch-by-epoch instead."
        );
        self.chain.slot_clock.set_slot(slot.into());
    }

    pub async fn add_block_at_slot(
        &self,
        slot: Slot,
        state: BeaconState<E>,
    ) -> Result<(SignedBeaconBlockHash, SignedBeaconBlock<E>, BeaconState<E>), BlockError<E>> {
        self.set_current_slot(slot);
        let (block, new_state) = self.make_block(state, slot).await;
        let block_hash = self
            .process_block(slot, block.canonical_root(), block.clone())
            .await?;
        Ok((block_hash, block, new_state))
    }

    pub fn attest_block(
        &self,
        state: &BeaconState<E>,
        state_root: Hash256,
        block_hash: SignedBeaconBlockHash,
        block: &SignedBeaconBlock<E>,
        validators: &[usize],
    ) {
        let attestations =
            self.make_attestations(validators, state, state_root, block_hash, block.slot());
        self.process_attestations(attestations);
    }

    pub fn sync_committee_sign_block(
        &self,
        state: &BeaconState<E>,
        block_hash: Hash256,
        slot: Slot,
        relative_sync_committee: RelativeSyncCommittee,
    ) {
        let sync_contributions =
            self.make_sync_contributions(state, block_hash, slot, relative_sync_committee);
        self.process_sync_contributions(sync_contributions).unwrap()
    }

    pub async fn add_attested_block_at_slot(
        &self,
        slot: Slot,
        state: BeaconState<E>,
        state_root: Hash256,
        validators: &[usize],
    ) -> Result<(SignedBeaconBlockHash, BeaconState<E>), BlockError<E>> {
        self.add_attested_block_at_slot_with_sync(
            slot,
            state,
            state_root,
            validators,
            SyncCommitteeStrategy::NoValidators,
        )
        .await
    }

    pub async fn add_attested_block_at_slot_with_sync(
        &self,
        slot: Slot,
        state: BeaconState<E>,
        state_root: Hash256,
        validators: &[usize],
        sync_committee_strategy: SyncCommitteeStrategy,
    ) -> Result<(SignedBeaconBlockHash, BeaconState<E>), BlockError<E>> {
        let (block_hash, block, state) = self.add_block_at_slot(slot, state).await?;
        self.attest_block(&state, state_root, block_hash, &block, validators);

        if sync_committee_strategy == SyncCommitteeStrategy::AllValidators
            && state.current_sync_committee().is_ok()
        {
            self.sync_committee_sign_block(
                &state,
                block_hash.into(),
                slot,
                if (slot + 1).epoch(E::slots_per_epoch())
                    % self.spec.epochs_per_sync_committee_period
                    == 0
                {
                    RelativeSyncCommittee::Next
                } else {
                    RelativeSyncCommittee::Current
                },
            );
        }

        Ok((block_hash, state))
    }

    pub async fn add_attested_blocks_at_slots(
        &self,
        state: BeaconState<E>,
        state_root: Hash256,
        slots: &[Slot],
        validators: &[usize],
    ) -> AddBlocksResult<E> {
        self.add_attested_blocks_at_slots_with_sync(
            state,
            state_root,
            slots,
            validators,
            SyncCommitteeStrategy::NoValidators,
        )
        .await
    }

    pub async fn add_attested_blocks_at_slots_with_sync(
        &self,
        state: BeaconState<E>,
        state_root: Hash256,
        slots: &[Slot],
        validators: &[usize],
        sync_committee_strategy: SyncCommitteeStrategy,
    ) -> AddBlocksResult<E> {
        assert!(!slots.is_empty());
        self.add_attested_blocks_at_slots_given_lbh(
            state,
            state_root,
            slots,
            validators,
            None,
            sync_committee_strategy,
        )
        .await
    }

    async fn add_attested_blocks_at_slots_given_lbh(
        &self,
        mut state: BeaconState<E>,
        state_root: Hash256,
        slots: &[Slot],
        validators: &[usize],
        mut latest_block_hash: Option<SignedBeaconBlockHash>,
        sync_committee_strategy: SyncCommitteeStrategy,
    ) -> AddBlocksResult<E> {
        assert!(
            slots.windows(2).all(|w| w[0] <= w[1]),
            "Slots have to be sorted"
        ); // slice.is_sorted() isn't stabilized at the moment of writing this
        let mut block_hash_from_slot: HashMap<Slot, SignedBeaconBlockHash> = HashMap::new();
        let mut state_hash_from_slot: HashMap<Slot, BeaconStateHash> = HashMap::new();
        for slot in slots {
            let (block_hash, new_state) = self
                .add_attested_block_at_slot_with_sync(
                    *slot,
                    state,
                    state_root,
                    validators,
                    sync_committee_strategy,
                )
                .await
                .unwrap();
            state = new_state;
            block_hash_from_slot.insert(*slot, block_hash);
            state_hash_from_slot.insert(*slot, state.tree_hash_root().into());
            latest_block_hash = Some(block_hash);
        }
        (
            block_hash_from_slot,
            state_hash_from_slot,
            latest_block_hash.unwrap(),
            state,
        )
    }

    /// A monstrosity of great usefulness.
    ///
    /// Calls `add_attested_blocks_at_slots` for each of the chains in `chains`,
    /// taking care to batch blocks by epoch so that the slot clock gets advanced one
    /// epoch at a time.
    ///
    /// Chains is a vec of `(state, slots, validators)` tuples.
    pub async fn add_blocks_on_multiple_chains(
        &self,
        chains: Vec<(BeaconState<E>, Vec<Slot>, Vec<usize>)>,
    ) -> Vec<AddBlocksResult<E>> {
        let slots_per_epoch = E::slots_per_epoch();

        let min_epoch = chains
            .iter()
            .map(|(_, slots, _)| slots.iter().min().unwrap())
            .min()
            .unwrap()
            .epoch(slots_per_epoch);
        let max_epoch = chains
            .iter()
            .map(|(_, slots, _)| slots.iter().max().unwrap())
            .max()
            .unwrap()
            .epoch(slots_per_epoch);

        let mut chains = chains
            .into_iter()
            .map(|(state, slots, validators)| {
                (
                    state,
                    slots,
                    validators,
                    HashMap::new(),
                    HashMap::new(),
                    SignedBeaconBlockHash::from(Hash256::zero()),
                )
            })
            .collect::<Vec<_>>();

        for epoch in min_epoch.as_u64()..=max_epoch.as_u64() {
            let mut new_chains = vec![];

            for (
                mut head_state,
                slots,
                validators,
                mut block_hashes,
                mut state_hashes,
                head_block,
            ) in chains
            {
                let epoch_slots = slots
                    .iter()
                    .filter(|s| s.epoch(slots_per_epoch).as_u64() == epoch)
                    .copied()
                    .collect::<Vec<_>>();

                let head_state_root = head_state.update_tree_hash_cache().unwrap();
                let (new_block_hashes, new_state_hashes, new_head_block, new_head_state) = self
                    .add_attested_blocks_at_slots_given_lbh(
                        head_state,
                        head_state_root,
                        &epoch_slots,
                        &validators,
                        Some(head_block),
                        SyncCommitteeStrategy::NoValidators, // for backwards compat
                    )
                    .await;

                block_hashes.extend(new_block_hashes);
                state_hashes.extend(new_state_hashes);

                new_chains.push((
                    new_head_state,
                    slots,
                    validators,
                    block_hashes,
                    state_hashes,
                    new_head_block,
                ));
            }

            chains = new_chains;
        }

        chains
            .into_iter()
            .map(|(state, _, _, block_hashes, state_hashes, head_block)| {
                (block_hashes, state_hashes, head_block, state)
            })
            .collect()
    }

    pub fn get_finalized_checkpoints(&self) -> HashSet<SignedBeaconBlockHash> {
        let chain_dump = self.chain.chain_dump().unwrap();
        chain_dump
            .iter()
            .cloned()
            .map(|checkpoint| checkpoint.beacon_state.finalized_checkpoint().root.into())
            .filter(|block_hash| *block_hash != Hash256::zero().into())
            .collect()
    }

    /// Advance the slot of the `BeaconChain`.
    ///
    /// Does not produce blocks or attestations.
    pub fn advance_slot(&self) {
        self.chain.slot_clock.advance_slot();
    }

    /// Advance the clock to `lookahead` before the start of `slot`.
    pub fn advance_to_slot_lookahead(&self, slot: Slot, lookahead: Duration) {
        let time = self.chain.slot_clock.start_of(slot).unwrap() - lookahead;
        self.chain.slot_clock.set_current_time(time);
    }

    /// Uses `Self::extend_chain` to build the chain out to the `target_slot`.
    pub async fn extend_to_slot(&self, target_slot: Slot) -> Hash256 {
        if self.chain.slot().unwrap() == self.chain.canonical_head.cached_head().head_slot() {
            self.advance_slot();
        }

        let num_slots = target_slot
            .as_usize()
            .checked_sub(self.chain.slot().unwrap().as_usize())
            .expect("target_slot must be >= current_slot")
            .checked_add(1)
            .unwrap();

        self.extend_slots(num_slots).await
    }

    /// Uses `Self::extend_chain` to `num_slots` blocks.
    ///
    /// Utilizes:
    ///
    ///  - BlockStrategy::OnCanonicalHead,
    ///  - AttestationStrategy::AllValidators,
    pub async fn extend_slots(&self, num_slots: usize) -> Hash256 {
        if self.chain.slot().unwrap() == self.chain.canonical_head.cached_head().head_slot() {
            self.advance_slot();
        }

        self.extend_chain(
            num_slots,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await
    }

    /// Extend the `BeaconChain` with some blocks and attestations. Returns the root of the
    /// last-produced block (the head of the chain).
    ///
    /// Chain will be extended by `num_blocks` blocks.
    ///
    /// The `block_strategy` dictates where the new blocks will be placed.
    ///
    /// The `attestation_strategy` dictates which validators will attest to the newly created
    /// blocks.
    pub async fn extend_chain(
        &self,
        num_blocks: usize,
        block_strategy: BlockStrategy,
        attestation_strategy: AttestationStrategy,
    ) -> Hash256 {
        self.extend_chain_with_sync(
            num_blocks,
            block_strategy,
            attestation_strategy,
            SyncCommitteeStrategy::NoValidators,
        )
        .await
    }

    pub async fn extend_chain_with_sync(
        &self,
        num_blocks: usize,
        block_strategy: BlockStrategy,
        attestation_strategy: AttestationStrategy,
        sync_committee_strategy: SyncCommitteeStrategy,
    ) -> Hash256 {
        let (mut state, slots) = match block_strategy {
            BlockStrategy::OnCanonicalHead => {
                let current_slot: u64 = self.get_current_slot().into();
                let slots: Vec<Slot> = (current_slot..(current_slot + (num_blocks as u64)))
                    .map(Slot::new)
                    .collect();
                let state = self.get_current_state();
                (state, slots)
            }
            BlockStrategy::ForkCanonicalChainAt {
                previous_slot,
                first_slot,
            } => {
                let first_slot_: u64 = first_slot.into();
                let slots: Vec<Slot> = (first_slot_..(first_slot_ + (num_blocks as u64)))
                    .map(Slot::new)
                    .collect();
                let state = self
                    .chain
                    .state_at_slot(previous_slot, StateSkipConfig::WithStateRoots)
                    .unwrap();
                (state, slots)
            }
        };
        let validators = match attestation_strategy {
            AttestationStrategy::AllValidators => self.get_all_validators(),
            AttestationStrategy::SomeValidators(vals) => vals,
        };
        let state_root = state.update_tree_hash_cache().unwrap();
        let (_, _, last_produced_block_hash, _) = self
            .add_attested_blocks_at_slots_with_sync(
                state,
                state_root,
                &slots,
                &validators,
                sync_committee_strategy,
            )
            .await;
        last_produced_block_hash.into()
    }

    /// Deprecated: Use add_attested_blocks_at_slots() instead
    ///
    /// Creates two forks:
    ///
    ///  - The "honest" fork: created by the `honest_validators` who have built `honest_fork_blocks`
    /// on the head
    ///  - The "faulty" fork: created by the `faulty_validators` who skipped a slot and
    /// then built `faulty_fork_blocks`.
    ///
    /// Returns `(honest_head, faulty_head)`, the roots of the blocks at the top of each chain.
    pub async fn generate_two_forks_by_skipping_a_block(
        &self,
        honest_validators: &[usize],
        faulty_validators: &[usize],
        honest_fork_blocks: usize,
        faulty_fork_blocks: usize,
    ) -> (Hash256, Hash256) {
        let initial_head_slot = self.chain.head_snapshot().beacon_block.slot();

        // Move to the next slot so we may produce some more blocks on the head.
        self.advance_slot();

        // Extend the chain with blocks where only honest validators agree.
        let honest_head = self
            .extend_chain(
                honest_fork_blocks,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::SomeValidators(honest_validators.to_vec()),
            )
            .await;

        // Go back to the last block where all agreed, and build blocks upon it where only faulty nodes
        // agree.
        let faulty_head = self
            .extend_chain(
                faulty_fork_blocks,
                BlockStrategy::ForkCanonicalChainAt {
                    previous_slot: initial_head_slot,
                    // `initial_head_slot + 2` means one slot is skipped.
                    first_slot: initial_head_slot + 2,
                },
                AttestationStrategy::SomeValidators(faulty_validators.to_vec()),
            )
            .await;

        assert_ne!(honest_head, faulty_head, "forks should be distinct");

        (honest_head, faulty_head)
    }

    pub fn process_sync_contributions(
        &self,
        sync_contributions: HarnessSyncContributions<E>,
    ) -> Result<(), SyncCommitteeError> {
        let mut verified_contributions = Vec::with_capacity(sync_contributions.len());

        for (_, contribution_and_proof) in sync_contributions {
            let signed_contribution_and_proof = contribution_and_proof.unwrap();

            let verified_contribution = self
                .chain
                .verify_sync_contribution_for_gossip(signed_contribution_and_proof)?;

            verified_contributions.push(verified_contribution);
        }

        for verified_contribution in verified_contributions {
            self.chain
                .add_contribution_to_block_inclusion_pool(verified_contribution)?;
        }

        Ok(())
    }
}

// Junk `Debug` impl to satistfy certain trait bounds during testing.
impl<T: BeaconChainTypes> fmt::Debug for BeaconChainHarness<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BeaconChainHarness")
    }
}

pub struct MakeAttestationOptions {
    /// Produce exactly `limit` attestations.
    pub limit: Option<usize>,
    /// Fork to use for signing attestations.
    pub fork: Fork,
}
