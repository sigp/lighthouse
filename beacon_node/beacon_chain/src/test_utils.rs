use crate::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use lmd_ghost::LmdGhost;
use slot_clock::SlotClock;
use slot_clock::TestingSlotClock;
use state_processing::per_slot_processing;
use std::marker::PhantomData;
use std::sync::Arc;
use store::MemoryStore;
use store::Store;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    test_utils::TestingBeaconStateBuilder, AggregateSignature, Attestation,
    AttestationDataAndCustodyBit, BeaconBlock, BeaconState, Bitfield, ChainSpec, Domain, EthSpec,
    Hash256, Keypair, RelativeEpoch, SecretKey, Signature, Slot,
};

pub use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};

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

/// Used to make the `BeaconChainHarness` generic over some types.
pub struct CommonTypes<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    _phantom_l: PhantomData<L>,
    _phantom_e: PhantomData<E>,
}

impl<L, E> BeaconChainTypes for CommonTypes<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    type Store = MemoryStore;
    type SlotClock = TestingSlotClock;
    type LmdGhost = L;
    type EthSpec = E;
}

/// A testing harness which can instantiate a `BeaconChain` and populate it with blocks and
/// attestations.
pub struct BeaconChainHarness<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    pub chain: BeaconChain<CommonTypes<L, E>>,
    pub keypairs: Vec<Keypair>,
    pub spec: ChainSpec,
}

impl<L, E> BeaconChainHarness<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    /// Instantiate a new harness with `validator_count` initial validators.
    pub fn new(validator_count: usize) -> Self {
        let spec = E::default_spec();

        let store = Arc::new(MemoryStore::open());

        let state_builder =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec);
        let (genesis_state, keypairs) = state_builder.build();

        let mut genesis_block = BeaconBlock::empty(&spec);
        genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

        // Slot clock
        let slot_clock = TestingSlotClock::new(
            spec.genesis_slot,
            genesis_state.genesis_time,
            spec.seconds_per_slot,
        );

        let chain = BeaconChain::from_genesis(
            store,
            slot_clock,
            genesis_state,
            genesis_block,
            spec.clone(),
        )
        .expect("Terminate if beacon chain generation fails");

        Self {
            chain,
            keypairs,
            spec,
        }
    }

    /// Advance the slot of the `BeaconChain`.
    ///
    /// Does not produce blocks or attestations.
    pub fn advance_slot(&self) {
        self.chain.slot_clock.advance_slot();
        self.chain.catchup_state().expect("should catchup state");
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
                BlockStrategy::OnCanonicalHead => self.chain.read_slot_clock().unwrap() - 1,
                BlockStrategy::ForkCanonicalChainAt { previous_slot, .. } => previous_slot,
            };

            self.get_state_at_slot(state_slot)
        };

        // Determine the first slot where a block should be built.
        let mut slot = match block_strategy {
            BlockStrategy::OnCanonicalHead => self.chain.read_slot_clock().unwrap(),
            BlockStrategy::ForkCanonicalChainAt { first_slot, .. } => first_slot,
        };

        let mut head_block_root = None;

        for _ in 0..num_blocks {
            while self.chain.read_slot_clock().expect("should have a slot") < slot {
                self.advance_slot();
            }

            let (block, new_state) = self.build_block(state.clone(), slot, block_strategy);

            let outcome = self
                .chain
                .process_block(block)
                .expect("should not error during block processing");

            if let BlockProcessingOutcome::Processed { block_root } = outcome {
                head_block_root = Some(block_root);

                self.add_attestations_to_op_pool(
                    &attestation_strategy,
                    &new_state,
                    block_root,
                    slot,
                );
            } else {
                panic!("block should be successfully processed: {:?}", outcome);
            }

            state = new_state;
            slot += 1;
        }

        head_block_root.expect("did not produce any blocks")
    }

    fn get_state_at_slot(&self, state_slot: Slot) -> BeaconState<E> {
        let state_root = self
            .chain
            .rev_iter_state_roots(self.chain.current_state().slot - 1)
            .find(|(_hash, slot)| *slot == state_slot)
            .map(|(hash, _slot)| hash)
            .expect("could not find state root");

        self.chain
            .store
            .get(&state_root)
            .expect("should read db")
            .expect("should find state root")
    }

    /// Returns a newly created block, signed by the proposer for the given slot.
    fn build_block(
        &self,
        mut state: BeaconState<E>,
        slot: Slot,
        block_strategy: BlockStrategy,
    ) -> (BeaconBlock, BeaconState<E>) {
        if slot < state.slot {
            panic!("produce slot cannot be prior to the state slot");
        }

        while state.slot < slot {
            per_slot_processing(&mut state, &self.spec)
                .expect("should be able to advance state to slot");
        }

        state.build_all_caches(&self.spec).unwrap();

        let proposer_index = match block_strategy {
            BlockStrategy::OnCanonicalHead => self
                .chain
                .block_proposer(slot)
                .expect("should get block proposer from chain"),
            _ => state
                .get_beacon_proposer_index(slot, RelativeEpoch::Current, &self.spec)
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

    /// Adds attestations to the `BeaconChain` operations pool to be included in future blocks.
    ///
    /// The `attestation_strategy` dictates which validators should attest.
    fn add_attestations_to_op_pool(
        &self,
        attestation_strategy: &AttestationStrategy,
        state: &BeaconState<E>,
        head_block_root: Hash256,
        head_block_slot: Slot,
    ) {
        let spec = &self.spec;
        let fork = &state.fork;

        let attesting_validators: Vec<usize> = match attestation_strategy {
            AttestationStrategy::AllValidators => (0..self.keypairs.len()).collect(),
            AttestationStrategy::SomeValidators(vec) => vec.clone(),
        };

        state
            .get_crosslink_committees_at_slot(state.slot)
            .expect("should get committees")
            .iter()
            .for_each(|cc| {
                let committee_size = cc.committee.len();

                for (i, validator_index) in cc.committee.iter().enumerate() {
                    // Note: searching this array is worst-case `O(n)`. A hashset could be a better
                    // alternative.
                    if attesting_validators.contains(validator_index) {
                        let data = self
                            .chain
                            .produce_attestation_data_for_block(
                                cc.shard,
                                head_block_root,
                                head_block_slot,
                                state,
                            )
                            .expect("should produce attestation data");

                        let mut aggregation_bitfield = Bitfield::new();
                        aggregation_bitfield.set(i, true);
                        aggregation_bitfield.set(committee_size, false);

                        let mut custody_bitfield = Bitfield::new();
                        custody_bitfield.set(committee_size, false);

                        let signature = {
                            let message = AttestationDataAndCustodyBit {
                                data: data.clone(),
                                custody_bit: false,
                            }
                            .tree_hash_root();

                            let domain =
                                spec.get_domain(data.target_epoch, Domain::Attestation, fork);

                            let mut agg_sig = AggregateSignature::new();
                            agg_sig.add(&Signature::new(
                                &message,
                                domain,
                                self.get_sk(*validator_index),
                            ));

                            agg_sig
                        };

                        let attestation = Attestation {
                            aggregation_bitfield,
                            data,
                            custody_bitfield,
                            signature,
                        };

                        self.chain
                            .process_attestation(attestation)
                            .expect("should process attestation");
                    }
                }
            });
    }

    /// Returns the secret key for the given validator index.
    fn get_sk(&self, validator_index: usize) -> &SecretKey {
        &self.keypairs[validator_index].sk
    }
}
