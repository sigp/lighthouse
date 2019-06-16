use crate::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use lmd_ghost::{LmdGhost, ThreadSafeReducedTree};
use slot_clock::SlotClock;
use slot_clock::TestingSlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use store::MemoryStore;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    test_utils::TestingBeaconStateBuilder, BeaconBlock, ChainSpec, Domain, EthSpec, Hash256,
    Keypair, MinimalEthSpec, Signature,
};

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

    pub fn extend_canonical_chain(&self) {
        self.chain.slot_clock.advance_slot();
        self.chain.catchup_state().expect("should catchup state");

        let block = self.build_block();
        let outcome = self
            .chain
            .process_block(block)
            .expect("should process block");
        assert_eq!(outcome, BlockProcessingOutcome::Processed);
    }

    fn build_block(&self) -> BeaconBlock {
        let slot = self.chain.read_slot_clock().unwrap();

        let sk = {
            let proposer = self
                .chain
                .block_proposer(slot)
                .expect("should get block propoer");
            &self.keypairs[proposer].sk
        };

        let fork = &self.chain.head().beacon_state.fork;

        let randao_reveal = {
            let epoch = slot.epoch(E::slots_per_epoch());
            let message = epoch.tree_hash_root();
            let domain = self.spec.get_domain(epoch, Domain::Randao, fork);
            Signature::new(&message, domain, sk)
        };

        let (mut block, _state) = self
            .chain
            .produce_block(randao_reveal)
            .expect("should producer block");

        block.signature = {
            let message = block.signed_root();
            let epoch = block.slot.epoch(E::slots_per_epoch());
            let domain = self.spec.get_domain(epoch, Domain::BeaconProposer, fork);
            Signature::new(&message, domain, sk)
        };

        block
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub const VALIDATOR_COUNT: usize = 16;

    #[test]
    fn build_on_genesis() {
        let harness: BeaconChainHarness<
            ThreadSafeReducedTree<MemoryStore, MinimalEthSpec>,
            MinimalEthSpec,
        > = BeaconChainHarness::new(VALIDATOR_COUNT);

        for _ in 0..MinimalEthSpec::slots_per_epoch() * 2 {
            harness.extend_canonical_chain();
        }
    }
}
