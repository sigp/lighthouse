use crate::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::CachingEth1Backend,
    events::NullEventHandler,
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, BlockProcessingOutcome,
};
use genesis::interop_genesis_state;
use lmd_ghost::ThreadSafeReducedTree;
use rayon::prelude::*;
use sloggers::{terminal::TerminalLoggerBuilder, types::Severity, Build};
use slot_clock::TestingSlotClock;
use state_processing::per_slot_processing;
use std::sync::Arc;
use std::time::Duration;
use store::{
    migrate::{BlockingMigrator, NullMigrator},
    DiskStore, MemoryStore, Migrate, Store,
};
use tree_hash::{SignedRoot, TreeHash};
use types::{
    AggregateSignature, Attestation, BeaconBlock, BeaconState, BitList, ChainSpec, Domain, EthSpec,
    Hash256, Keypair, SecretKey, Signature, Slot,
};

pub use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
pub use types::test_utils::generate_deterministic_keypairs;

// 4th September 2019
pub const HARNESS_GENESIS_TIME: u64 = 1_567_552_690;
// This parameter is required by a builder but not used because we use the `TestingSlotClock`.
pub const HARNESS_SLOT_TIME: Duration = Duration::from_secs(1);

pub type BaseHarnessType<TStore, TStoreMigrator, TEthSpec> = Witness<
    TStore,
    TStoreMigrator,
    TestingSlotClock,
    ThreadSafeReducedTree<TStore, TEthSpec>,
    CachingEth1Backend<TEthSpec, TStore>,
    TEthSpec,
    NullEventHandler<TEthSpec>,
>;

pub type HarnessType<E> = BaseHarnessType<MemoryStore<E>, NullMigrator, E>;
pub type DiskHarnessType<E> = BaseHarnessType<DiskStore<E>, BlockingMigrator<DiskStore<E>>, E>;

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
}

impl<E: EthSpec> BeaconChainHarness<HarnessType<E>> {
    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn new(eth_spec_instance: E, keypairs: Vec<Keypair>) -> Self {
        let spec = E::default_spec();

        let log = TerminalLoggerBuilder::new()
            .level(Severity::Warning)
            .build()
            .expect("logger should build");

        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec.clone())
            .store(Arc::new(MemoryStore::open()))
            .store_migrator(NullMigrator)
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
            .reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            keypairs,
        }
    }
}

impl<E: EthSpec> BeaconChainHarness<DiskHarnessType<E>> {
    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn new_with_disk_store(
        eth_spec_instance: E,
        store: Arc<DiskStore<E>>,
        keypairs: Vec<Keypair>,
    ) -> Self {
        let spec = E::default_spec();

        let log = TerminalLoggerBuilder::new()
            .level(Severity::Warning)
            .build()
            .expect("logger should build");

        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec.clone())
            .store(store.clone())
            .store_migrator(<BlockingMigrator<_> as Migrate<_, E>>::new(store))
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
            .reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            keypairs,
        }
    }

    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn resume_from_disk_store(
        eth_spec_instance: E,
        store: Arc<DiskStore<E>>,
        keypairs: Vec<Keypair>,
    ) -> Self {
        let spec = E::default_spec();

        let log = TerminalLoggerBuilder::new()
            .level(Severity::Warning)
            .build()
            .expect("logger should build");

        let chain = BeaconChainBuilder::new(eth_spec_instance)
            .logger(log.clone())
            .custom_spec(spec.clone())
            .store(store.clone())
            .store_migrator(<BlockingMigrator<_> as Migrate<_, E>>::new(store))
            .resume_from_db()
            .expect("should resume beacon chain from db")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .null_event_handler()
            .testing_slot_clock(Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
            .build()
            .expect("should build");

        Self {
            spec: chain.spec.clone(),
            chain,
            keypairs,
        }
    }
}

impl<S, M, E> BeaconChainHarness<BaseHarnessType<S, M, E>>
where
    S: Store<E>,
    M: Migrate<S, E>,
    E: EthSpec,
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
        let mut state = {
            // Determine the slot for the first block (or skipped block).
            let state_slot = match block_strategy {
                BlockStrategy::OnCanonicalHead => {
                    self.chain.slot().expect("should have a slot") - 1
                }
                BlockStrategy::ForkCanonicalChainAt { previous_slot, .. } => previous_slot,
            };

            self.chain
                .state_at_slot(state_slot)
                .expect("should find state for slot")
                .clone()
        };

        // Determine the first slot where a block should be built.
        let mut slot = match block_strategy {
            BlockStrategy::OnCanonicalHead => self.chain.slot().expect("should have a slot"),
            BlockStrategy::ForkCanonicalChainAt { first_slot, .. } => first_slot,
        };

        let mut head_block_root = None;

        for _ in 0..num_blocks {
            while self.chain.slot().expect("should have a slot") < slot {
                self.advance_slot();
            }

            let (block, new_state) = self.build_block(state.clone(), slot, block_strategy);

            let outcome = self
                .chain
                .process_block(block)
                .expect("should not error during block processing");

            self.chain.fork_choice().expect("should find head");

            if let BlockProcessingOutcome::Processed { block_root } = outcome {
                head_block_root = Some(block_root);

                self.add_free_attestations(&attestation_strategy, &new_state, block_root, slot);
            } else {
                panic!("block should be successfully processed: {:?}", outcome);
            }

            state = new_state;
            slot += 1;
        }

        head_block_root.expect("did not produce any blocks")
    }

    /// Returns a newly created block, signed by the proposer for the given slot.
    fn build_block(
        &self,
        mut state: BeaconState<E>,
        slot: Slot,
        block_strategy: BlockStrategy,
    ) -> (BeaconBlock<E>, BeaconState<E>) {
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
            let message = epoch.tree_hash_root();
            let domain = self.spec.get_domain(epoch, Domain::Randao, fork);
            Signature::new(&message, domain, sk)
        };

        let (mut block, state) = self
            .chain
            .produce_block_on_state(state, slot, randao_reveal)
            .expect("should produce block");

        block.signature = {
            let message = block.signed_root();
            let epoch = block.slot.epoch(E::slots_per_epoch());
            let domain = self.spec.get_domain(epoch, Domain::BeaconProposer, fork);
            Signature::new(&message, domain, sk)
        };

        (block, state)
    }

    /// Adds attestations to the `BeaconChain` operations pool and fork choice.
    ///
    /// The `attestation_strategy` dictates which validators should attest.
    fn add_free_attestations(
        &self,
        attestation_strategy: &AttestationStrategy,
        state: &BeaconState<E>,
        head_block_root: Hash256,
        head_block_slot: Slot,
    ) {
        self.get_free_attestations(
            attestation_strategy,
            state,
            head_block_root,
            head_block_slot,
        )
        .into_iter()
        .for_each(|attestation| {
            match self
                .chain
                .process_attestation(attestation)
                .expect("should not error during attestation processing")
            {
                AttestationProcessingOutcome::Processed => (),
                other => panic!("did not successfully process attestation: {:?}", other),
            }
        });
    }

    /// Generates a `Vec<Attestation>` for some attestation strategy and head_block.
    pub fn get_free_attestations(
        &self,
        attestation_strategy: &AttestationStrategy,
        state: &BeaconState<E>,
        head_block_root: Hash256,
        head_block_slot: Slot,
    ) -> Vec<Attestation<E>> {
        let spec = &self.spec;
        let fork = &state.fork;

        let attesting_validators: Vec<usize> = match attestation_strategy {
            AttestationStrategy::AllValidators => (0..self.keypairs.len()).collect(),
            AttestationStrategy::SomeValidators(vec) => vec.clone(),
        };

        let mut attestations = vec![];

        state
            .get_beacon_committees_at_slot(state.slot)
            .expect("should get committees")
            .iter()
            .for_each(|bc| {
                let committee_size = bc.committee.len();

                let mut local_attestations: Vec<Attestation<E>> = bc
                    .committee
                    .par_iter()
                    .enumerate()
                    .filter_map(|(i, validator_index)| {
                        // Note: searching this array is worst-case `O(n)`. A hashset could be a better
                        // alternative.
                        if attesting_validators.contains(validator_index) {
                            let data = self
                                .chain
                                .produce_attestation_data_for_block(
                                    bc.index,
                                    head_block_root,
                                    head_block_slot,
                                    state,
                                )
                                .expect("should produce attestation data");

                            let mut aggregation_bits = BitList::with_capacity(committee_size)
                                .expect("should make aggregation bits");
                            aggregation_bits
                                .set(i, true)
                                .expect("should be able to set aggregation bits");

                            let signature = {
                                let message = data.tree_hash_root();

                                let domain = spec.get_domain(
                                    data.target.epoch,
                                    Domain::BeaconAttester,
                                    fork,
                                );

                                let mut agg_sig = AggregateSignature::new();
                                agg_sig.add(&Signature::new(
                                    &message,
                                    domain,
                                    self.get_sk(*validator_index),
                                ));

                                agg_sig
                            };

                            let attestation = Attestation {
                                aggregation_bits,
                                data,
                                signature,
                            };

                            Some(attestation)
                        } else {
                            None
                        }
                    })
                    .collect();

                attestations.append(&mut local_attestations);
            });

        attestations
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
            .slot;

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

        assert!(honest_head != faulty_head, "forks should be distinct");

        (honest_head, faulty_head)
    }

    /// Returns the secret key for the given validator index.
    fn get_sk(&self, validator_index: usize) -> &SecretKey {
        &self.keypairs[validator_index].sk
    }
}
