use self::utils::TestRig;
use beacon_chain::BeaconChain;
#[cfg(test)]
use block_producer::{test_utils::TestSigner, BlockProducer};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use slot_clock::TestingSlotClock;
use std::sync::{Arc, RwLock};
use types::{ChainSpec, Keypair, Validator};

mod utils;

#[test]
fn rig_can_generate_validators() {
    /*
    let (_db, mut chain) = in_memory_test_chain(ChainSpec::foundation());
    let validators = generate_validators(2, &chain);
    chain.spec = inject_validators_into_spec(chain.spec.clone(), &validators[..]);
    */
    let validator_count = 2;
    let mut rig = TestRig::new(ChainSpec::foundation(), validator_count);
    rig.produce_next_slot();
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
