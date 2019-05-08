pub use crate::{BeaconChain, BeaconChainError, CheckPoint};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use fork_choice::BitwiseLMDGhost;
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::*;
use types::{test_utils::TestingBeaconStateBuilder, BeaconStateTypes, FewValidatorsStateTypes};

type TestingBeaconChain<B> =
    BeaconChain<MemoryDB, TestingSlotClock, BitwiseLMDGhost<MemoryDB, FewValidatorsStateTypes>, B>;

pub struct TestingBeaconChainBuilder<B: BeaconStateTypes> {
    state_builder: TestingBeaconStateBuilder<B>,
}

impl<B: BeaconStateTypes> TestingBeaconChainBuilder<B> {
    pub fn build(self, spec: &ChainSpec) -> TestingBeaconChain<B> {
        let db = Arc::new(MemoryDB::open());
        let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
        let state_store = Arc::new(BeaconStateStore::new(db.clone()));
        let slot_clock = TestingSlotClock::new(spec.genesis_slot.as_u64());
        let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());

        let (genesis_state, _keypairs) = self.state_builder.build();

        let mut genesis_block = BeaconBlock::empty(&spec);
        genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

        // Create the Beacon Chain
        BeaconChain::from_genesis(
            state_store.clone(),
            block_store.clone(),
            slot_clock,
            genesis_state,
            genesis_block,
            spec.clone(),
            fork_choice,
        )
        .unwrap()
    }
}

impl<B: BeaconStateTypes> From<TestingBeaconStateBuilder<B>> for TestingBeaconChainBuilder<B> {
    fn from(state_builder: TestingBeaconStateBuilder<B>) -> TestingBeaconChainBuilder<B> {
        TestingBeaconChainBuilder { state_builder }
    }
}
