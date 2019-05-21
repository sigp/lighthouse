pub use crate::{BeaconChain, BeaconChainError, CheckPoint};
use fork_choice::BitwiseLMDGhost;
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use store::MemoryStore;
use tree_hash::TreeHash;
use types::*;
use types::{test_utils::TestingBeaconStateBuilder, EthSpec, FewValidatorsEthSpec};

type TestingBeaconChain<E> = BeaconChain<
    MemoryStore,
    TestingSlotClock,
    BitwiseLMDGhost<MemoryStore, FewValidatorsEthSpec>,
    E,
>;

pub struct TestingBeaconChainBuilder<E: EthSpec> {
    state_builder: TestingBeaconStateBuilder<E>,
}

impl<E: EthSpec> TestingBeaconChainBuilder<E> {
    pub fn build(self, spec: &ChainSpec) -> TestingBeaconChain<E> {
        let store = Arc::new(MemoryStore::open());
        let slot_clock = TestingSlotClock::new(spec.genesis_slot.as_u64());
        let fork_choice = BitwiseLMDGhost::new(store.clone());

        let (genesis_state, _keypairs) = self.state_builder.build();

        let mut genesis_block = BeaconBlock::empty(&spec);
        genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

        // Create the Beacon Chain
        BeaconChain::from_genesis(
            store,
            slot_clock,
            genesis_state,
            genesis_block,
            spec.clone(),
            fork_choice,
        )
        .unwrap()
    }
}

impl<E: EthSpec> From<TestingBeaconStateBuilder<E>> for TestingBeaconChainBuilder<E> {
    fn from(state_builder: TestingBeaconStateBuilder<E>) -> TestingBeaconChainBuilder<E> {
        TestingBeaconChainBuilder { state_builder }
    }
}
