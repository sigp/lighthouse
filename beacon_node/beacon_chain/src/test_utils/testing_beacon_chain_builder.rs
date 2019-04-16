pub use crate::{BeaconChain, BeaconChainError, CheckPoint};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use fork_choice::BitwiseLMDGhost;
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::test_utils::TestingBeaconStateBuilder;
use types::*;

type TestingBeaconChain = BeaconChain<MemoryDB, TestingSlotClock, BitwiseLMDGhost<MemoryDB>>;

pub struct TestingBeaconChainBuilder {
    state_builder: TestingBeaconStateBuilder,
}

impl TestingBeaconChainBuilder {
    pub fn build(self, spec: &ChainSpec) -> TestingBeaconChain {
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

impl From<TestingBeaconStateBuilder> for TestingBeaconChainBuilder {
    fn from(state_builder: TestingBeaconStateBuilder) -> TestingBeaconChainBuilder {
        TestingBeaconChainBuilder { state_builder }
    }
}
