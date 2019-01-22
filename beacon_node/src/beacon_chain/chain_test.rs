use super::{BeaconChain, BlockProcessingOutcome};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use slot_clock::TestingSlotClock;
use spec::ChainSpec;
use std::sync::Arc;

fn in_memory_test_stores() -> (
    Arc<MemoryDB>,
    Arc<BeaconBlockStore<MemoryDB>>,
    Arc<BeaconStateStore<MemoryDB>>,
) {
    let db = Arc::new(MemoryDB::open());
    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));
    (db, block_store, state_store)
}

fn in_memory_test_chain(
    spec: ChainSpec,
) -> (Arc<MemoryDB>, BeaconChain<MemoryDB, TestingSlotClock>) {
    let (db, block_store, state_store) = in_memory_test_stores();
    let slot_clock = TestingSlotClock::new(0);

    let chain = BeaconChain::genesis(state_store, block_store, slot_clock, spec);
    (db, chain.unwrap())
}

#[test]
fn it_constructs() {
    let (_db, _chain) = in_memory_test_chain(ChainSpec::foundation());
}

#[test]
fn it_produces() {
    let (_db, mut chain) = in_memory_test_chain(ChainSpec::foundation());
    let (_block, _state) = chain.produce_block().unwrap();
}

#[test]
fn it_processes_a_block_it_produces() {
    let (_db, mut chain) = in_memory_test_chain(ChainSpec::foundation());
    let (block, _state) = chain.produce_block().unwrap();
    let (outcome, new_block_hash) = chain.process_block(&block).unwrap();
    assert_eq!(outcome, BlockProcessingOutcome::Processed);
    assert_eq!(chain.canonical_leaf_block, new_block_hash);
}
