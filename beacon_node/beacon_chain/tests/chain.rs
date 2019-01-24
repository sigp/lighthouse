use beacon_chain::{BeaconChain, BlockProcessingOutcome};
#[cfg(test)]
use block_producer::{
    test_utils::{TestEpochMap, TestSigner},
    BeaconNode as BeaconBlockNode, BeaconNodeError as BeaconBlockNodeError, BlockProducer,
};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use slot_clock::TestingSlotClock;
use spec::ChainSpec;
use std::sync::{Arc, RwLock};
use types::{BeaconBlock, Keypair};

struct DirectBeaconNode();

impl BeaconBlockNode for DirectBeaconNode {
    fn produce_beacon_block(&self, slot: u64) -> Result<Option<BeaconBlock>, BeaconBlockNodeError> {
        Err(BeaconBlockNodeError::DecodeFailure)
    }

    /// Returns the value specified by the `set_next_publish_result`.
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<bool, BeaconBlockNodeError> {
        Err(BeaconBlockNodeError::DecodeFailure)
    }
}

struct Validator {
    block_producer: BlockProducer<TestingSlotClock, DirectBeaconNode, TestEpochMap, TestSigner>,
    spec: Arc<ChainSpec>,
    epoch_map: Arc<TestEpochMap>,
    keypair: Keypair,
    beacon_node: Arc<DirectBeaconNode>,
    slot_clock: Arc<RwLock<TestingSlotClock>>,
    signer: Arc<TestSigner>,
}

impl Validator {
    pub fn new() -> Self {
        let spec = Arc::new(ChainSpec::foundation());
        let keypair = Keypair::random();
        let slot_clock = Arc::new(RwLock::new(TestingSlotClock::new(0)));
        let signer = Arc::new(TestSigner::new(keypair.clone()));
        let beacon_node = Arc::new(DirectBeaconNode());
        let epoch_map = Arc::new(TestEpochMap::new());

        let block_producer = BlockProducer::new(
            spec.clone(),
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        Self {
            block_producer,
            spec,
            epoch_map,
            keypair,
            beacon_node,
            slot_clock,
            signer,
        }
    }
}

fn generate_validators(n: usize) -> Vec<Validator> {
    let mut validators = Vec::with_capacity(n);
    for _ in 0..n {
        validators.push(Validator::new());
    }
    validators
}

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

/*
#[test]
fn it_produces() {
    let (_db, mut chain) = in_memory_test_chain(ChainSpec::foundation());
    let (_block, _state) = chain.produce_block().unwrap();
}

#[test]
fn it_processes_a_block_it_produces() {
    let (_db, mut chain) = in_memory_test_chain(ChainSpec::foundation());
    let (block, _state) = chain.produce_block().unwrap();
    let (outcome, new_block_hash) = chain.process_block(block).unwrap();
    assert_eq!(outcome, BlockProcessingOutcome::Processed);
    assert_eq!(chain.canonical_leaf_block, new_block_hash);
}
*/
