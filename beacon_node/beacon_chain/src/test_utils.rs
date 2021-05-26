pub use crate::persisted_beacon_chain::PersistedBeaconChain;
pub use crate::{
    beacon_chain::{BEACON_CHAIN_DB_KEY, ETH1_CACHE_DB_KEY, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY},
    migrate::MigratorConfig,
    BeaconChainError,
};
use crate::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::CachingEth1Backend,
    BeaconChain, BeaconChainTypes, BlockError, ChainConfig, ServerSentEventHandler,
    StateSkipConfig,
};
use futures::channel::mpsc::Receiver;
use genesis::interop_genesis_state;
use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use rayon::prelude::*;
use slog::Logger;
use slot_clock::TestingSlotClock;
use state_processing::state_advance::complete_state_advance;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use store::{config::StoreConfig, BlockReplay, HotColdDB, ItemStore, LevelDB, MemoryStore};
use task_executor::ShutdownReason;
use tempfile::{tempdir, TempDir};
use tree_hash::TreeHash;
use types::{
    AggregateSignature, Attestation, AttestationData, AttesterSlashing, BeaconState,
    BeaconStateHash, ChainSpec, Checkpoint, Domain, Epoch, EthSpec, Graffiti, Hash256,
    IndexedAttestation, Keypair, ProposerSlashing, SelectionProof, SignedAggregateAndProof,
    SignedBeaconBlock, SignedBeaconBlockHash, SignedRoot, SignedVoluntaryExit, Slot, SubnetId,
    VariableList, VoluntaryExit,
};

pub use types::test_utils::generate_deterministic_keypairs;

// 4th September 2019
pub const HARNESS_GENESIS_TIME: u64 = 1_567_552_690;
// This parameter is required by a builder but not used because we use the `TestingSlotClock`.
pub const HARNESS_SLOT_TIME: Duration = Duration::from_secs(1);

pub type BaseHarnessType<TEthSpec, THotStore, TColdStore> =
    Witness<TestingSlotClock, CachingEth1Backend<TEthSpec>, TEthSpec, THotStore, TColdStore>;

pub type DiskHarnessType<E> = BaseHarnessType<E, LevelDB<E>, LevelDB<E>>;
pub type EphemeralHarnessType<E> = BaseHarnessType<E, MemoryStore<E>, MemoryStore<E>>;

pub type AddBlocksResult<E> = (
    HashMap<Slot, SignedBeaconBlockHash>,
    HashMap<Slot, BeaconStateHash>,
    SignedBeaconBlockHash,
    BeaconState<E>,
);

/// Deprecated: Indicates how the `BeaconChainHarness` should produce blocks.
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

/// Deprecated: Indicates how the `BeaconChainHarness` should produce attestations.
#[derive(Clone, Debug)]
pub enum AttestationStrategy {
    /// All validators attest to whichever block the `BeaconChainHarness` has produced.
    AllValidators,
    /// Only the given validators should attest. All others should fail to produce attestations.
    SomeValidators(Vec<usize>),
}

fn make_rng() -> Mutex<StdRng> {
    // Nondeterminism in tests is a highly undesirable thing.  Seed the RNG to some arbitrary
    // but fixed value for reproducibility.
    Mutex::new(StdRng::seed_from_u64(0x0DDB1A5E5BAD5EEDu64))
}

/// Return a logger suitable for test usage.
///
/// By default no logs will be printed, but they can be enabled via the `test_logger` feature.
///
/// We've tried the `slog_term::TestStdoutWriter` in the past, but found it too buggy because
/// of the threading limitation.
pub fn test_logger() -> Logger {
    use sloggers::Build;

    if cfg!(feature = "test_logger") {
        sloggers::terminal::TerminalLoggerBuilder::new()
            .level(sloggers::types::Severity::Debug)
            .build()
            .unwrap()
    } else {
        sloggers::null::NullLoggerBuilder.build().unwrap()
    }
}

/// A testing harness which can instantiate a `BeaconChain` and populate it with blocks and
/// attestations.
///
/// Used for testing.
pub struct BeaconChainHarness<T: BeaconChainTypes> {
    pub validator_keypairs: Vec<Keypair>,

    pub chain: BeaconChain<T>,
    pub spec: ChainSpec,
    pub data_dir: TempDir,
    pub shutdown_receiver: Receiver<ShutdownReason>,

    pub rng: Mutex<StdRng>,
}

type HarnessAttestations<E> = Vec<(
    Vec<(Attestation<E>, SubnetId)>,
    Option<SignedAggregateAndProof<E>>,
)>;

impl<E: EthSpec> BeaconChainHarness<EphemeralHarnessType<E>> {
    pub fn new(eth_spec_instance: E, validator_keypairs: Vec<Keypair>) -> Self {
        Self::new_with_store_config(
            eth_spec_instance,
            validator_keypairs,
            StoreConfig::default(),
        )
    }

    pub fn new_with_store_config(
        eth_spec_instance: E,
        validator_keypairs: Vec<Keypair>,
        config: StoreConfig,
    ) -> Self {
        // Setting the target aggregators to really high means that _all_ validators in the
        // committee are required to produce an aggregate. This is overkill, however with small
        // validator counts it's the only way to be certain there is _at least one_ aggregator per
        // committee.
        Self::new_with_target_aggregators(eth_spec_instance, validator_keypairs, 1 << 32, config)
    }

    /// Instantiate a new harness with  a custom `target_aggregators_per_committee` spec value
    pub fn new_with_target_aggregators(
        eth_spec_instance: E,
        validator_keypairs: Vec<Keypair>,
        target_aggregators_per_committee: u64,
        store_config: StoreConfig,
    ) -> Self {
        Self::new_with_chain_config(
            eth_spec_instance,
            validator_keypairs,
            target_aggregators_per_committee,
            store_config,
            ChainConfig::default(),
        )
    }

    /// Instantiate a new harness with `validator_count` initial validators, a custom
    /// `target_aggregators_per_committee` spec value, and a `ChainConfig`
    pub fn new_with_chain_config(
        eth_spec_instance: E,
        validator_keypairs: Vec<Keypair>,
        target_aggregators_per_committee: u64,
        store_config: StoreConfig,
        chain_config: ChainConfig,
    ) -> Self {
        let data_dir = tempdir().expect("should create temporary data_dir");
        let mut spec = E::default_spec();

        spec.target_aggregators_per_committee = target_aggregators_per_committee;

        let (shutdown_tx, shutdown_receiver) = futures::channel::mpsc::channel(1);

        let log = test_logger();

        let store = HotColdDB::open_ephemeral(store_config, spec.clone(), log.clone()).unwrap();
        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec.clone())
            .store(Arc::new(store))
            .store_migrator_config(MigratorConfig::default().blocking())
            .genesis_state(
                interop_genesis_state::<E>(&validator_keypairs, HARNESS_GENESIS_TIME, &spec)
                    .expect("should generate interop state"),
            )
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .testing_slot_clock(HARNESS_SLOT_TIME)
            .expect("should configure testing slot clock")
            .shutdown_sender(shutdown_tx)
            .chain_config(chain_config)
            .event_handler(Some(ServerSentEventHandler::new_with_capacity(
                log.clone(),
                1,
            )))
            .monitor_validators(true, vec![], log)
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            validator_keypairs,
            data_dir,
            shutdown_receiver,
            rng: make_rng(),
        }
    }
}

impl<E: EthSpec> BeaconChainHarness<DiskHarnessType<E>> {
    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn new_with_disk_store(
        eth_spec_instance: E,
        store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>,
        validator_keypairs: Vec<Keypair>,
    ) -> Self {
        let data_dir = tempdir().expect("should create temporary data_dir");
        let spec = E::default_spec();

        let log = test_logger();
        let (shutdown_tx, shutdown_receiver) = futures::channel::mpsc::channel(1);

        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec.clone())
            .import_max_skip_slots(None)
            .store(store)
            .store_migrator_config(MigratorConfig::default().blocking())
            .genesis_state(
                interop_genesis_state::<E>(&validator_keypairs, HARNESS_GENESIS_TIME, &spec)
                    .expect("should generate interop state"),
            )
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .testing_slot_clock(HARNESS_SLOT_TIME)
            .expect("should configure testing slot clock")
            .shutdown_sender(shutdown_tx)
            .monitor_validators(true, vec![], log)
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            validator_keypairs,
            data_dir,
            shutdown_receiver,
            rng: make_rng(),
        }
    }
}

impl<E: EthSpec> BeaconChainHarness<DiskHarnessType<E>> {
    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn resume_from_disk_store(
        eth_spec_instance: E,
        store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>,
        validator_keypairs: Vec<Keypair>,
        data_dir: TempDir,
    ) -> Self {
        let spec = E::default_spec();

        let log = test_logger();
        let (shutdown_tx, shutdown_receiver) = futures::channel::mpsc::channel(1);

        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec)
            .import_max_skip_slots(None)
            .store(store)
            .store_migrator_config(MigratorConfig::default().blocking())
            .resume_from_db()
            .expect("should resume beacon chain from db")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .testing_slot_clock(Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .shutdown_sender(shutdown_tx)
            .monitor_validators(true, vec![], log)
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            validator_keypairs,
            data_dir,
            shutdown_receiver,
            rng: make_rng(),
        }
    }
}

impl<E, Hot, Cold> BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    pub fn logger(&self) -> &slog::Logger {
        &self.chain.log
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

    pub fn get_current_state(&self) -> BeaconState<E> {
        self.chain.head().unwrap().beacon_state
    }

    pub fn get_current_state_and_root(&self) -> (BeaconState<E>, Hash256) {
        let head = self.chain.head().unwrap();
        let state_root = head.beacon_state_root();
        (head.beacon_state, state_root)
    }

    pub fn get_current_slot(&self) -> Slot {
        self.chain.slot().unwrap()
    }

    pub fn get_block(&self, block_hash: SignedBeaconBlockHash) -> Option<SignedBeaconBlock<E>> {
        self.chain.get_block(&block_hash.into()).unwrap()
    }

    pub fn block_exists(&self, block_hash: SignedBeaconBlockHash) -> bool {
        self.get_block(block_hash).is_some()
    }

    pub fn get_hot_state(&self, state_hash: BeaconStateHash) -> Option<BeaconState<E>> {
        self.chain
            .store
            .load_hot_state(&state_hash.into(), BlockReplay::Accurate)
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

    pub fn make_block(
        &self,
        mut state: BeaconState<E>,
        slot: Slot,
    ) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        assert_ne!(slot, 0, "can't produce a block at slot 0");
        assert!(slot >= state.slot);

        complete_state_advance(&mut state, None, slot, &self.spec)
            .expect("should be able to advance state to slot");

        state
            .build_all_caches(&self.spec)
            .expect("should build caches");

        let proposer_index = state.get_beacon_proposer_index(slot, &self.spec).unwrap();

        // If we produce two blocks for the same slot, they hash up to the same value and
        // BeaconChain errors out with `BlockIsAlreadyKnown`.  Vary the graffiti so that we produce
        // different blocks each time.
        let graffiti = Graffiti::from(self.rng.lock().gen::<[u8; 32]>());

        let randao_reveal = {
            let epoch = slot.epoch(E::slots_per_epoch());
            let domain = self.spec.get_domain(
                epoch,
                Domain::Randao,
                &state.fork,
                state.genesis_validators_root,
            );
            let message = epoch.signing_root(domain);
            let sk = &self.validator_keypairs[proposer_index].sk;
            sk.sign(message)
        };

        let (block, state) = self
            .chain
            .produce_block_on_state(state, None, slot, randao_reveal, Some(graffiti))
            .unwrap();

        let signed_block = block.sign(
            &self.validator_keypairs[proposer_index].sk,
            &state.fork,
            state.genesis_validators_root,
            &self.spec,
        );

        (signed_block, state)
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
    ) -> Vec<Vec<(Attestation<E>, SubnetId)>> {
        let committee_count = state.get_committee_count_at_slot(state.slot).unwrap();

        state
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
                        let mut attestation = self
                            .chain
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
                                &state.fork,
                                state.genesis_validators_root,
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
                    .collect()
            })
            .collect()
    }

    /// Deprecated: Use make_unaggregated_attestations() instead.
    ///
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
        let unaggregated_attestations = self.make_unaggregated_attestations(
            &attesting_validators,
            &state,
            state_root,
            block_hash,
            slot,
        );

        let aggregated_attestations: Vec<Option<SignedAggregateAndProof<E>>> = unaggregated_attestations
            .iter()
            .map(|committee_attestations| {
                // If there are any attestations in this committee, create an aggregate.
                if let Some((attestation, _)) = committee_attestations.first() {
                    let bc = state.get_beacon_committee(attestation.data.slot, attestation.data.index)
                        .unwrap();

                    let aggregator_index = bc.committee
                        .iter()
                        .find(|&validator_index| {
                            if !attesting_validators.contains(validator_index) {
                                return false
                            }

                            let selection_proof = SelectionProof::new::<E>(
                                state.slot,
                                &self.validator_keypairs[*validator_index].sk,
                                &state.fork,
                                state.genesis_validators_root,
                                &self.spec,
                            );

                            selection_proof.is_aggregator(bc.committee.len(), &self.spec).unwrap_or(false)
                        })
                        .copied()
                        .unwrap_or_else(|| panic!(
                            "Committee {} at slot {} with {} attesting validators does not have any aggregators",
                            bc.index, state.slot, bc.committee.len()
                        ));

                    // If the chain is able to produce an aggregate, use that. Otherwise, build an
                    // aggregate locally.
                    let aggregate = self
                        .chain
                        .get_aggregated_attestation(&attestation.data)
                        .unwrap_or_else(|| {
                            committee_attestations.iter().skip(1).fold(attestation.clone(), |mut agg, (att, _)| {
                                agg.aggregate(att);
                                agg
                            })
                        });

                    let signed_aggregate = SignedAggregateAndProof::from_aggregate(
                        aggregator_index as u64,
                        aggregate,
                        None,
                        &self.validator_keypairs[aggregator_index].sk,
                        &state.fork,
                        state.genesis_validators_root,
                        &self.spec,
                    );

                    Some(signed_aggregate)
                }
                else {
                    None
                }
            }).collect();

        unaggregated_attestations
            .into_iter()
            .zip(aggregated_attestations)
            .collect()
    }

    pub fn make_attester_slashing(&self, validator_indices: Vec<u64>) -> AttesterSlashing<E> {
        let mut attestation_1 = IndexedAttestation {
            attesting_indices: VariableList::new(validator_indices).unwrap(),
            data: AttestationData {
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
            },
            signature: AggregateSignature::infinity(),
        };

        let mut attestation_2 = attestation_1.clone();
        attestation_2.data.index += 1;

        for attestation in &mut [&mut attestation_1, &mut attestation_2] {
            for &i in &attestation.attesting_indices {
                let sk = &self.validator_keypairs[i as usize].sk;

                let fork = self.chain.head_info().unwrap().fork;
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
        let mut block_header_1 = self
            .chain
            .head_beacon_block()
            .unwrap()
            .message
            .block_header();
        block_header_1.proposer_index = validator_index;

        let mut block_header_2 = block_header_1.clone();
        block_header_2.state_root = Hash256::zero();

        let sk = &self.validator_keypairs[validator_index as usize].sk;
        let fork = self.chain.head_info().unwrap().fork;
        let genesis_validators_root = self.chain.genesis_validators_root;

        let mut signed_block_headers = vec![block_header_1, block_header_2]
            .into_iter()
            .map(|block_header| {
                block_header.sign::<E>(&sk, &fork, genesis_validators_root, &self.chain.spec)
            })
            .collect::<Vec<_>>();

        ProposerSlashing {
            signed_header_2: signed_block_headers.remove(1),
            signed_header_1: signed_block_headers.remove(0),
        }
    }

    pub fn make_voluntary_exit(&self, validator_index: u64, epoch: Epoch) -> SignedVoluntaryExit {
        let sk = &self.validator_keypairs[validator_index as usize].sk;
        let fork = self.chain.head_info().unwrap().fork;
        let genesis_validators_root = self.chain.genesis_validators_root;

        VoluntaryExit {
            epoch,
            validator_index,
        }
        .sign(sk, &fork, genesis_validators_root, &self.chain.spec)
    }

    pub fn process_block(
        &self,
        slot: Slot,
        block: SignedBeaconBlock<E>,
    ) -> Result<SignedBeaconBlockHash, BlockError<E>> {
        self.set_current_slot(slot);
        let block_hash: SignedBeaconBlockHash = self.chain.process_block(block)?.into();
        self.chain.fork_choice()?;
        Ok(block_hash)
    }

    pub fn process_block_result(
        &self,
        block: SignedBeaconBlock<E>,
    ) -> Result<SignedBeaconBlockHash, BlockError<E>> {
        let block_hash: SignedBeaconBlockHash = self.chain.process_block(block)?.into();
        self.chain.fork_choice().unwrap();
        Ok(block_hash)
    }

    pub fn process_attestations(&self, attestations: HarnessAttestations<E>) {
        for (unaggregated_attestations, maybe_signed_aggregate) in attestations.into_iter() {
            for (attestation, subnet_id) in unaggregated_attestations {
                self.chain
                    .verify_unaggregated_attestation_for_gossip(
                        attestation.clone(),
                        Some(subnet_id),
                    )
                    .unwrap()
                    .add_to_pool(&self.chain)
                    .unwrap();
            }

            if let Some(signed_aggregate) = maybe_signed_aggregate {
                let attn = self
                    .chain
                    .verify_aggregated_attestation_for_gossip(signed_aggregate)
                    .unwrap();

                self.chain.apply_attestation_to_fork_choice(&attn).unwrap();

                self.chain.add_to_block_inclusion_pool(attn).unwrap();
            }
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

    pub fn add_block_at_slot(
        &self,
        slot: Slot,
        state: BeaconState<E>,
    ) -> Result<(SignedBeaconBlockHash, SignedBeaconBlock<E>, BeaconState<E>), BlockError<E>> {
        self.set_current_slot(slot);
        let (block, new_state) = self.make_block(state, slot);
        let block_hash = self.process_block(slot, block.clone())?;
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
        let attestations = self.make_attestations(
            validators,
            &state,
            state_root,
            block_hash,
            block.message.slot,
        );
        self.process_attestations(attestations);
    }

    pub fn add_attested_block_at_slot(
        &self,
        slot: Slot,
        state: BeaconState<E>,
        state_root: Hash256,
        validators: &[usize],
    ) -> Result<(SignedBeaconBlockHash, BeaconState<E>), BlockError<E>> {
        let (block_hash, block, state) = self.add_block_at_slot(slot, state)?;
        self.attest_block(&state, state_root, block_hash, &block, validators);
        Ok((block_hash, state))
    }

    pub fn add_attested_blocks_at_slots(
        &self,
        state: BeaconState<E>,
        state_root: Hash256,
        slots: &[Slot],
        validators: &[usize],
    ) -> AddBlocksResult<E> {
        assert!(!slots.is_empty());
        self.add_attested_blocks_at_slots_given_lbh(state, state_root, slots, validators, None)
    }

    fn add_attested_blocks_at_slots_given_lbh(
        &self,
        mut state: BeaconState<E>,
        state_root: Hash256,
        slots: &[Slot],
        validators: &[usize],
        mut latest_block_hash: Option<SignedBeaconBlockHash>,
    ) -> AddBlocksResult<E> {
        assert!(
            slots.windows(2).all(|w| w[0] <= w[1]),
            "Slots have to be sorted"
        ); // slice.is_sorted() isn't stabilized at the moment of writing this
        let mut block_hash_from_slot: HashMap<Slot, SignedBeaconBlockHash> = HashMap::new();
        let mut state_hash_from_slot: HashMap<Slot, BeaconStateHash> = HashMap::new();
        for slot in slots {
            let (block_hash, new_state) = self
                .add_attested_block_at_slot(*slot, state, state_root, validators)
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
    pub fn add_blocks_on_multiple_chains(
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
                    );

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
            .map(|checkpoint| checkpoint.beacon_state.finalized_checkpoint.root.into())
            .filter(|block_hash| *block_hash != Hash256::zero().into())
            .collect()
    }

    /// Deprecated: Do not modify the slot clock manually; rely on add_attested_blocks_at_slots()
    ///             instead
    ///
    /// Advance the slot of the `BeaconChain`.
    ///
    /// Does not produce blocks or attestations.
    pub fn advance_slot(&self) {
        self.chain.slot_clock.advance_slot();
    }

    /// Deprecated: Use make_block() instead
    ///
    /// Returns a newly created block, signed by the proposer for the given slot.
    pub fn build_block(
        &self,
        state: BeaconState<E>,
        slot: Slot,
        _block_strategy: BlockStrategy,
    ) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        self.make_block(state, slot)
    }

    /// Deprecated: Use add_attested_blocks_at_slots() instead
    ///
    /// Extend the `BeaconChain` with some blocks and attestations. Returns the root of the
    /// last-produced block (the head of the chain).
    ///
    /// Chain will be extended by `num_blocks` blocks.
    ///
    /// The `block_strategy` dictates where the new blocks will be placed.
    ///
    /// The `attestation_strategy` dictates which validators will attest to the newly created
    /// blocks.
    pub fn extend_chain(
        &self,
        num_blocks: usize,
        block_strategy: BlockStrategy,
        attestation_strategy: AttestationStrategy,
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
        let (_, _, last_produced_block_hash, _) =
            self.add_attested_blocks_at_slots(state, state_root, &slots, &validators);
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
    pub fn generate_two_forks_by_skipping_a_block(
        &self,
        honest_validators: &[usize],
        faulty_validators: &[usize],
        honest_fork_blocks: usize,
        faulty_fork_blocks: usize,
    ) -> (Hash256, Hash256) {
        let initial_head_slot = self
            .chain
            .head()
            .expect("should get head")
            .beacon_block
            .slot();

        // Move to the next slot so we may produce some more blocks on the head.
        self.advance_slot();

        // Extend the chain with blocks where only honest validators agree.
        let honest_head = self.extend_chain(
            honest_fork_blocks,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(honest_validators.to_vec()),
        );

        // Go back to the last block where all agreed, and build blocks upon it where only faulty nodes
        // agree.
        let faulty_head = self.extend_chain(
            faulty_fork_blocks,
            BlockStrategy::ForkCanonicalChainAt {
                previous_slot: initial_head_slot,
                // `initial_head_slot + 2` means one slot is skipped.
                first_slot: initial_head_slot + 2,
            },
            AttestationStrategy::SomeValidators(faulty_validators.to_vec()),
        );

        assert_ne!(honest_head, faulty_head, "forks should be distinct");

        (honest_head, faulty_head)
    }
}
