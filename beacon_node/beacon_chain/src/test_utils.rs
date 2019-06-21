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

#[derive(Clone, Copy, Debug)]
pub enum BuildStrategy {
    OnCanonicalHead,
    ForkCanonicalChainAt(Slot),
}

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

pub struct BeaconChainHarness<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    chain: BeaconChain<CommonTypes<L, E>>,
    keypairs: Vec<Keypair>,
    spec: ChainSpec,
}

impl<L, E> BeaconChainHarness<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
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

    pub fn advance_slot(&self) {
        self.chain.slot_clock.advance_slot();
        self.chain.catchup_state().expect("should catchup state");
    }

    pub fn extend_chain(&self, build_strategy: BuildStrategy, blocks: usize) {
        // Get an initial state to build the block upon, based on the build strategy.
        let mut state = match build_strategy {
            BuildStrategy::OnCanonicalHead => self.chain.current_state().clone(),
            BuildStrategy::ForkCanonicalChainAt(fork_slot) => {
                let state_root = self
                    .chain
                    .rev_iter_state_roots(self.chain.head().beacon_state.slot - 1)
                    .find(|(_hash, slot)| *slot == fork_slot)
                    .map(|(hash, _slot)| hash)
                    .expect("could not find state root for fork");

                self.chain
                    .store
                    .get(&state_root)
                    .expect("should read db")
                    .expect("should find state root")
            }
        };

        // Get an initial slot to build upon, based on the build strategy.
        let mut slot = match build_strategy {
            BuildStrategy::OnCanonicalHead => self.chain.read_slot_clock().unwrap(),
            BuildStrategy::ForkCanonicalChainAt(slot) => slot,
        };

        for _ in 0..blocks {
            while self.chain.read_slot_clock().expect("should have a slot") < slot {
                self.advance_slot();
            }

            let (block, new_state) = self.build_block(state.clone(), slot, build_strategy);

            let outcome = self
                .chain
                .process_block(block)
                .expect("should not error during block processing");

            if let BlockProcessingOutcome::Processed { block_root } = outcome {
                //
            } else {
                panic!("block should be successfully processed");
            }

            self.add_attestations_to_op_pool();

            state = new_state;
            slot += 1;
        }
    }

    fn build_block(
        &self,
        mut state: BeaconState<E>,
        slot: Slot,
        build_strategy: BuildStrategy,
    ) -> (BeaconBlock, BeaconState<E>) {
        if slot < state.slot {
            panic!("produce slot cannot be prior to the state slot");
        }

        while state.slot < slot {
            per_slot_processing(&mut state, &self.spec)
                .expect("should be able to advance state to slot");
        }

        state.build_all_caches(&self.spec).unwrap();

        let proposer_index = match build_strategy {
            BuildStrategy::OnCanonicalHead => self
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

    fn add_attestations_to_op_pool(&self) {
        let state = &self.chain.current_state();
        let spec = &self.spec;
        let fork = &state.fork;

        state
            .get_crosslink_committees_at_slot(state.slot)
            .expect("should get committees")
            .iter()
            .for_each(|cc| {
                let committee_size = cc.committee.len();

                for (i, validator_index) in cc.committee.iter().enumerate() {
                    let data = self
                        .chain
                        .produce_attestation_data(cc.shard)
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

                        let domain = spec.get_domain(data.target_epoch, Domain::Attestation, fork);

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
            });
    }

    fn get_sk(&self, validator_index: usize) -> &SecretKey {
        &self.keypairs[validator_index].sk
    }
}

#[cfg(test)]
// #[cfg(not(debug_assertions))]
mod test {
    use super::*;
    use lmd_ghost::ThreadSafeReducedTree;
    use types::MinimalEthSpec;

    pub const VALIDATOR_COUNT: usize = 16;

    fn get_harness(
        validator_count: usize,
    ) -> BeaconChainHarness<ThreadSafeReducedTree<MemoryStore, MinimalEthSpec>, MinimalEthSpec>
    {
        let harness = BeaconChainHarness::new(validator_count);

        // Move past the zero slot.
        harness.advance_slot();

        harness
    }

    #[test]
    fn can_finalize() {
        let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

        let harness = get_harness(VALIDATOR_COUNT);

        harness.extend_chain(BuildStrategy::OnCanonicalHead, num_blocks_produced as usize);

        let state = &harness.chain.head().beacon_state;

        assert_eq!(
            state.slot, num_blocks_produced,
            "head should be at the current slot"
        );
        assert_eq!(
            state.current_epoch(),
            num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
            "head should be at the expected epoch"
        );
        assert_eq!(
            state.current_justified_epoch,
            state.current_epoch() - 1,
            "the head should be justified one behind the current epoch"
        );
        assert_eq!(
            state.finalized_epoch,
            state.current_epoch() - 2,
            "the head should be finalized two behind the current epoch"
        );
    }
}
