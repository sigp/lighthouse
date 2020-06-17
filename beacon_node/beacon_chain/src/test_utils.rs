pub use crate::beacon_chain::{
    BEACON_CHAIN_DB_KEY, ETH1_CACHE_DB_KEY, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY,
};
use crate::migrate::{BlockingMigrator, Migrate, NullMigrator};
pub use crate::persisted_beacon_chain::PersistedBeaconChain;
use crate::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::CachingEth1Backend,
    events::NullEventHandler,
    BeaconChain, BeaconChainTypes, StateSkipConfig,
};
use genesis::interop_genesis_state;
use rayon::prelude::*;
use sloggers::{null::NullLoggerBuilder, Build};
use slot_clock::TestingSlotClock;
use state_processing::per_slot_processing;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use store::{config::StoreConfig, HotColdDB, ItemStore, LevelDB, MemoryStore};
use tempfile::{tempdir, TempDir};
use tree_hash::TreeHash;
use types::{
    AggregateSignature, Attestation, BeaconState, BeaconStateHash, ChainSpec, Domain, EthSpec,
    Hash256, Keypair, SecretKey, SelectionProof, Signature, SignedAggregateAndProof,
    SignedBeaconBlock, SignedBeaconBlockHash, SignedRoot, Slot, SubnetId,
};

pub use types::test_utils::generate_deterministic_keypairs;

// 4th September 2019
pub const HARNESS_GENESIS_TIME: u64 = 1_567_552_690;
// This parameter is required by a builder but not used because we use the `TestingSlotClock`.
pub const HARNESS_SLOT_TIME: Duration = Duration::from_secs(1);

pub type BaseHarnessType<TStoreMigrator, TEthSpec, THotStore, TColdStore> = Witness<
    TStoreMigrator,
    TestingSlotClock,
    CachingEth1Backend<TEthSpec>,
    TEthSpec,
    NullEventHandler<TEthSpec>,
    THotStore,
    TColdStore,
>;

pub type HarnessType<E> = BaseHarnessType<NullMigrator, E, MemoryStore<E>, MemoryStore<E>>;
pub type DiskHarnessType<E> =
    BaseHarnessType<BlockingMigrator<E, LevelDB<E>, LevelDB<E>>, E, LevelDB<E>, LevelDB<E>>;

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

/// A testing harness which can instantiate a `BeaconChain` and populate it with blocks and
/// attestations.
///
/// Used for testing.
pub struct BeaconChainHarness<T: BeaconChainTypes> {
    pub chain: BeaconChain<T>,
    pub keypairs: Vec<Keypair>,
    pub spec: ChainSpec,
    pub data_dir: TempDir,
}

impl<E: EthSpec> BeaconChainHarness<HarnessType<E>> {
    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn new(eth_spec_instance: E, keypairs: Vec<Keypair>, config: StoreConfig) -> Self {
        // Setting the target aggregators to really high means that _all_ validators in the
        // committee are required to produce an aggregate. This is overkill, however with small
        // validator counts it's the only way to be certain there is _at least one_ aggregator per
        // committee.
        Self::new_with_target_aggregators(eth_spec_instance, keypairs, 1 << 32, config)
    }

    /// Instantiate a new harness with `validator_count` initial validators and a custom
    /// `target_aggregators_per_committee` spec value
    pub fn new_with_target_aggregators(
        eth_spec_instance: E,
        keypairs: Vec<Keypair>,
        target_aggregators_per_committee: u64,
        config: StoreConfig,
    ) -> Self {
        let data_dir = tempdir().expect("should create temporary data_dir");
        let mut spec = E::default_spec();

        spec.target_aggregators_per_committee = target_aggregators_per_committee;

        let log = NullLoggerBuilder.build().expect("logger should build");
        let store = HotColdDB::open_ephemeral(config, spec.clone(), log.clone()).unwrap();
        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log)
            .custom_spec(spec.clone())
            .store(Arc::new(store))
            .store_migrator(NullMigrator)
            .data_dir(data_dir.path().to_path_buf())
            .genesis_state(
                interop_genesis_state::<E>(&keypairs, HARNESS_GENESIS_TIME, &spec)
                    .expect("should generate interop state"),
            )
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .null_event_handler()
            .testing_slot_clock(HARNESS_SLOT_TIME)
            .expect("should configure testing slot clock")
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            keypairs,
            data_dir,
        }
    }
}

impl<E: EthSpec> BeaconChainHarness<DiskHarnessType<E>> {
    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn new_with_disk_store(
        eth_spec_instance: E,
        store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>,
        keypairs: Vec<Keypair>,
    ) -> Self {
        let data_dir = tempdir().expect("should create temporary data_dir");
        let spec = E::default_spec();

        let log = NullLoggerBuilder.build().expect("logger should build");

        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec.clone())
            .store(store.clone())
            .store_migrator(BlockingMigrator::new(store, log.clone()))
            .data_dir(data_dir.path().to_path_buf())
            .genesis_state(
                interop_genesis_state::<E>(&keypairs, HARNESS_GENESIS_TIME, &spec)
                    .expect("should generate interop state"),
            )
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .null_event_handler()
            .testing_slot_clock(HARNESS_SLOT_TIME)
            .expect("should configure testing slot clock")
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            keypairs,
            data_dir,
        }
    }

    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn resume_from_disk_store(
        eth_spec_instance: E,
        store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>,
        keypairs: Vec<Keypair>,
        data_dir: TempDir,
    ) -> Self {
        let spec = E::default_spec();

        let log = NullLoggerBuilder.build().expect("logger should build");

        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec)
            .store(store.clone())
            .store_migrator(<BlockingMigrator<_, _, _> as Migrate<E, _, _>>::new(
                store,
                log.clone(),
            ))
            .data_dir(data_dir.path().to_path_buf())
            .resume_from_db()
            .expect("should resume beacon chain from db")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .null_event_handler()
            .testing_slot_clock(Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            keypairs,
            data_dir,
        }
    }
}

impl<M, E, Hot, Cold> BeaconChainHarness<BaseHarnessType<M, E, Hot, Cold>>
where
    M: Migrate<E, Hot, Cold>,
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    /// Advance the slot of the `BeaconChain`.
    ///
    /// Does not produce blocks or attestations.
    pub fn advance_slot(&self) {
        self.chain.slot_clock.advance_slot();
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
    pub fn extend_chain(
        &self,
        num_blocks: usize,
        block_strategy: BlockStrategy,
        attestation_strategy: AttestationStrategy,
    ) -> Hash256 {
        let mut i = 0;
        self.extend_chain_while(
            |_, _| {
                i += 1;
                i <= num_blocks
            },
            block_strategy,
            attestation_strategy,
        )
    }

    /// Extend the `BeaconChain` with some blocks and attestations. Returns the root of the
    /// last-produced block (the head of the chain).
    ///
    /// Chain will be extended while `predidcate` returns `true`.
    ///
    /// The `block_strategy` dictates where the new blocks will be placed.
    ///
    /// The `attestation_strategy` dictates which validators will attest to the newly created
    /// blocks.
    pub fn extend_chain_while<F>(
        &self,
        mut predicate: F,
        block_strategy: BlockStrategy,
        attestation_strategy: AttestationStrategy,
    ) -> Hash256
    where
        F: FnMut(&SignedBeaconBlock<E>, &BeaconState<E>) -> bool,
    {
        let mut state = {
            // Determine the slot for the first block (or skipped block).
            let state_slot = match block_strategy {
                BlockStrategy::OnCanonicalHead => {
                    self.chain.slot().expect("should have a slot") - 1
                }
                BlockStrategy::ForkCanonicalChainAt { previous_slot, .. } => previous_slot,
            };

            self.chain
                .state_at_slot(state_slot, StateSkipConfig::WithStateRoots)
                .expect("should find state for slot")
        };

        // Determine the first slot where a block should be built.
        let mut slot = match block_strategy {
            BlockStrategy::OnCanonicalHead => self.chain.slot().expect("should have a slot"),
            BlockStrategy::ForkCanonicalChainAt { first_slot, .. } => first_slot,
        };

        let mut head_block_root = None;

        loop {
            let (block, new_state) = self.build_block(state.clone(), slot, block_strategy);

            if !predicate(&block, &new_state) {
                break;
            }

            while self.chain.slot().expect("should have a slot") < slot {
                self.advance_slot();
            }

            let block_root = self
                .chain
                .process_block(block)
                .expect("should not error during block processing");

            self.chain.fork_choice().expect("should find head");
            head_block_root = Some(block_root);

            self.add_attestations_for_slot(&attestation_strategy, &new_state, block_root, slot);

            state = new_state;
            slot += 1;
        }

        head_block_root.expect("did not produce any blocks")
    }

    /// A simple method to produce a block at the current slot without applying it to the chain.
    ///
    /// Always uses `BlockStrategy::OnCanonicalHead`.
    pub fn get_block(&self) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        let state = self
            .chain
            .state_at_slot(
                self.chain.slot().unwrap() - 1,
                StateSkipConfig::WithStateRoots,
            )
            .unwrap();

        let slot = self.chain.slot().unwrap();

        self.build_block(state, slot, BlockStrategy::OnCanonicalHead)
    }

    /// A simple method to produce and process all attestation at the current slot. Always uses
    /// `AttestationStrategy::AllValidators`.
    pub fn generate_all_attestations(&self) {
        let slot = self.chain.slot().unwrap();
        let (state, block_root) = {
            let head = self.chain.head().unwrap();
            (head.beacon_state.clone(), head.beacon_block_root)
        };
        self.add_attestations_for_slot(
            &AttestationStrategy::AllValidators,
            &state,
            block_root,
            slot,
        );
    }

    /// Returns current canonical head slot
    pub fn get_chain_slot(&self) -> Slot {
        self.chain.slot().unwrap()
    }

    /// Returns current canonical head state
    pub fn get_head_state(&self) -> BeaconState<E> {
        self.chain.head().unwrap().beacon_state
    }

    /// Adds a single block (synchronously) onto either the canonical chain (block_strategy ==
    /// OnCanonicalHead) or a fork (block_strategy == ForkCanonicalChainAt).
    pub fn add_block(
        &self,
        state: &BeaconState<E>,
        block_strategy: BlockStrategy,
        slot: Slot,
        validators: &[usize],
    ) -> (SignedBeaconBlockHash, BeaconState<E>) {
        while self.chain.slot().expect("should have a slot") < slot {
            self.advance_slot();
        }

        let (block, new_state) = self.build_block(state.clone(), slot, block_strategy);

        let block_root = self
            .chain
            .process_block(block)
            .expect("should not error during block processing");

        self.chain.fork_choice().expect("should find head");

        let attestation_strategy = AttestationStrategy::SomeValidators(validators.to_vec());
        self.add_attestations_for_slot(&attestation_strategy, &new_state, block_root, slot);
        (block_root.into(), new_state)
    }

    /// `add_block()` repeated `num_blocks` times.
    pub fn add_blocks(
        &self,
        mut state: BeaconState<E>,
        mut slot: Slot,
        num_blocks: usize,
        attesting_validators: &[usize],
        block_strategy: BlockStrategy,
    ) -> (
        HashMap<Slot, SignedBeaconBlockHash>,
        HashMap<Slot, BeaconStateHash>,
        Slot,
        SignedBeaconBlockHash,
        BeaconState<E>,
    ) {
        let mut blocks: HashMap<Slot, SignedBeaconBlockHash> = HashMap::with_capacity(num_blocks);
        let mut states: HashMap<Slot, BeaconStateHash> = HashMap::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            let (new_root_hash, new_state) =
                self.add_block(&state, block_strategy, slot, attesting_validators);
            blocks.insert(slot, new_root_hash);
            states.insert(slot, new_state.tree_hash_root().into());
            state = new_state;
            slot += 1;
        }
        let head_hash = blocks[&(slot - 1)];
        (blocks, states, slot, head_hash, state)
    }

    /// A wrapper on `add_blocks()` to avoid passing enums explicitly.
    pub fn add_canonical_chain_blocks(
        &self,
        state: BeaconState<E>,
        slot: Slot,
        num_blocks: usize,
        attesting_validators: &[usize],
    ) -> (
        HashMap<Slot, SignedBeaconBlockHash>,
        HashMap<Slot, BeaconStateHash>,
        Slot,
        SignedBeaconBlockHash,
        BeaconState<E>,
    ) {
        let block_strategy = BlockStrategy::OnCanonicalHead;
        self.add_blocks(
            state,
            slot,
            num_blocks,
            attesting_validators,
            block_strategy,
        )
    }

    /// A wrapper on `add_blocks()` to avoid passing enums explicitly.
    pub fn add_stray_blocks(
        &self,
        state: BeaconState<E>,
        slot: Slot,
        num_blocks: usize,
        attesting_validators: &[usize],
    ) -> (
        HashMap<Slot, SignedBeaconBlockHash>,
        HashMap<Slot, BeaconStateHash>,
        Slot,
        SignedBeaconBlockHash,
        BeaconState<E>,
    ) {
        let block_strategy = BlockStrategy::ForkCanonicalChainAt {
            previous_slot: slot,
            first_slot: slot + 2,
        };
        self.add_blocks(
            state,
            slot + 2,
            num_blocks,
            attesting_validators,
            block_strategy,
        )
    }

    /// Returns a newly created block, signed by the proposer for the given slot.
    fn build_block(
        &self,
        mut state: BeaconState<E>,
        slot: Slot,
        block_strategy: BlockStrategy,
    ) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        if slot < state.slot {
            panic!("produce slot cannot be prior to the state slot");
        }

        while state.slot < slot {
            per_slot_processing(&mut state, None, &self.spec)
                .expect("should be able to advance state to slot");
        }

        state
            .build_all_caches(&self.spec)
            .expect("should build caches");

        let proposer_index = match block_strategy {
            BlockStrategy::OnCanonicalHead => self
                .chain
                .block_proposer(slot)
                .expect("should get block proposer from chain"),
            _ => state
                .get_beacon_proposer_index(slot, &self.spec)
                .expect("should get block proposer from state"),
        };

        let sk = &self.keypairs[proposer_index].sk;
        let fork = &state.fork.clone();

        let randao_reveal = {
            let epoch = slot.epoch(E::slots_per_epoch());
            let domain =
                self.spec
                    .get_domain(epoch, Domain::Randao, fork, state.genesis_validators_root);
            let message = epoch.signing_root(domain);
            Signature::new(message.as_bytes(), sk)
        };

        let (block, state) = self
            .chain
            .produce_block_on_state(state, slot, randao_reveal)
            .expect("should produce block");

        let signed_block = block.sign(sk, &state.fork, state.genesis_validators_root, &self.spec);

        (signed_block, state)
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
        head_block_root: Hash256,
        attestation_slot: Slot,
    ) -> Vec<Vec<(Attestation<E>, SubnetId)>> {
        let spec = &self.spec;
        let fork = &state.fork;

        let attesting_validators = self.get_attesting_validators(attestation_strategy);

        let committee_count = state
            .get_committee_count_at_slot(state.slot)
            .expect("should get committee count");

        state
            .get_beacon_committees_at_slot(state.slot)
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
                                head_block_root,
                                Cow::Borrowed(state),
                            )
                            .expect("should produce attestation");

                        attestation
                            .aggregation_bits
                            .set(i, true)
                            .expect("should be able to set aggregation bits");

                        attestation.signature = {
                            let domain = spec.get_domain(
                                attestation.data.target.epoch,
                                Domain::BeaconAttester,
                                fork,
                                state.genesis_validators_root,
                            );

                            let message = attestation.data.signing_root(domain);

                            let mut agg_sig = AggregateSignature::new();

                            agg_sig.add(&Signature::new(
                                message.as_bytes(),
                                self.get_sk(*validator_index),
                            ));

                            agg_sig
                        };

                        let subnet_id = SubnetId::compute_subnet_for_attestation_data::<E>(
                            &attestation.data,
                            committee_count,
                            &self.chain.spec,
                        )
                        .expect("should get subnet_id");

                        Some((attestation, subnet_id))
                    })
                    .collect()
            })
            .collect()
    }

    fn get_attesting_validators(&self, attestation_strategy: &AttestationStrategy) -> Vec<usize> {
        match attestation_strategy {
            AttestationStrategy::AllValidators => (0..self.keypairs.len()).collect(),
            AttestationStrategy::SomeValidators(vec) => vec.clone(),
        }
    }

    /// Generates a `Vec<Attestation>` for some attestation strategy and head_block.
    pub fn add_attestations_for_slot(
        &self,
        attestation_strategy: &AttestationStrategy,
        state: &BeaconState<E>,
        head_block_root: Hash256,
        head_block_slot: Slot,
    ) {
        // These attestations will not be accepted by the chain so no need to generate them.
        if state.slot + E::slots_per_epoch() < self.chain.slot().expect("should get slot") {
            return;
        }

        let spec = &self.spec;
        let fork = &state.fork;

        let attesting_validators = self.get_attesting_validators(attestation_strategy);

        let unaggregated_attestations = self.get_unaggregated_attestations(
            attestation_strategy,
            state,
            head_block_root,
            head_block_slot,
        );

        // Loop through all unaggregated attestations, submit them to the chain and also submit a
        // single aggregate.
        unaggregated_attestations
            .into_iter()
            .for_each(|committee_attestations| {
                // Submit each unaggregated attestation to the chain.
                for (attestation, subnet_id) in &committee_attestations {
                    self.chain
                        .verify_unaggregated_attestation_for_gossip(attestation.clone(), *subnet_id)
                        .expect("should not error during attestation processing")
                        .add_to_pool(&self.chain)
                        .expect("should add attestation to naive pool");
                }

                // If there are any attestations in this committee, create an aggregate.
                if let Some((attestation, _)) = committee_attestations.first() {
                    let bc = state.get_beacon_committee(attestation.data.slot, attestation.data.index)
                        .expect("should get committee");

                    let aggregator_index = bc.committee
                        .iter()
                        .find(|&validator_index| {
                            if !attesting_validators.contains(validator_index) {
                                return false
                            }

                            let selection_proof = SelectionProof::new::<E>(
                                state.slot,
                                self.get_sk(*validator_index),
                                fork,
                                state.genesis_validators_root,
                                spec,
                            );

                            selection_proof.is_aggregator(bc.committee.len(), spec).unwrap_or(false)
                        })
                        .copied()
                        .expect(&format!(
                            "Committee {} at slot {} with {} attesting validators does not have any aggregators",
                            bc.index, state.slot, bc.committee.len()
                        ));

                    // If the chain is able to produce an aggregate, use that. Otherwise, build an
                    // aggregate locally.
                    let aggregate = self
                        .chain
                        .get_aggregated_attestation(&attestation.data)
                        .expect("should not error whilst finding aggregate")
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
                        self.get_sk(aggregator_index),
                        fork,
                        state.genesis_validators_root,
                        spec,
                    );

                    let attn = self.chain
                        .verify_aggregated_attestation_for_gossip(signed_aggregate)
                        .expect("should not error during attestation processing");

                    self.chain.apply_attestation_to_fork_choice(&attn)
                        .expect("should add attestation to fork choice");

                    self.chain.add_to_block_inclusion_pool(attn)
                        .expect("should add attestation to op pool");
                }
            });
    }

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

    /// Returns the secret key for the given validator index.
    fn get_sk(&self, validator_index: usize) -> &SecretKey {
        &self.keypairs[validator_index].sk
    }
}
