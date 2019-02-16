use env_logger::{Builder, Env};
use log::debug;
use test_harness::BeaconChainHarness;
use types::ChainSpec;

#[test]
fn it_can_build_on_genesis_block() {
    Builder::from_env(Env::default().default_filter_or("trace")).init();

    let spec = ChainSpec::few_validators();
    let validator_count = 8;

    let mut harness = BeaconChainHarness::new(spec, validator_count as usize);

    harness.advance_chain_with_block();
}

#[test]
#[ignore]
fn it_can_produce_past_first_epoch_boundary() {
    Builder::from_env(Env::default().default_filter_or("debug")).init();

    let spec = ChainSpec::few_validators();
    let validator_count = 8;

    debug!("Starting harness build...");

    let mut harness = BeaconChainHarness::new(spec, validator_count);

    debug!("Harness built, tests starting..");

    let blocks = harness.spec.epoch_length * 2 + 1;

    for i in 0..blocks {
        harness.advance_chain_with_block();
        debug!("Produced block {}/{}.", i, blocks);
    }
    let dump = harness.chain_dump().expect("Chain dump failed.");

    assert_eq!(dump.len() as u64, blocks + 1); // + 1 for genesis block.

    harness.dump_to_file("/tmp/chaindump.json".to_string(), &dump);
}
