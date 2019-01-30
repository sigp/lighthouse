use env_logger::{Builder, Env};
use log::debug;
use test_harness::BeaconChainHarness;
use types::ChainSpec;

#[test]
fn it_can_build_on_genesis_block() {
    let mut spec = ChainSpec::foundation();
    spec.genesis_slot = spec.epoch_length * 8;

    /*
    spec.shard_count = spec.shard_count / 8;
    spec.target_committee_size = spec.target_committee_size / 8;
    */
    let validator_count = 1000;

    let mut harness = BeaconChainHarness::new(spec, validator_count as usize);

    harness.advance_chain_with_block();
}

#[test]
#[ignore]
fn it_can_produce_past_first_epoch_boundary() {
    Builder::from_env(Env::default().default_filter_or("debug")).init();

    let validator_count = 100;

    debug!("Starting harness build...");

    let mut harness = BeaconChainHarness::new(ChainSpec::foundation(), validator_count);

    debug!("Harness built, tests starting..");

    let blocks = harness.spec.epoch_length * 3 + 1;

    for i in 0..blocks {
        harness.advance_chain_with_block();
        debug!("Produced block {}/{}.", i, blocks);
    }
    let dump = harness.chain_dump().expect("Chain dump failed.");

    assert_eq!(dump.len() as u64, blocks + 1); // + 1 for genesis block.

    harness.dump_to_file("/tmp/chaindump.json".to_string(), &dump);
}
