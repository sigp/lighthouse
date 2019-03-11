use env_logger::{Builder, Env};
use log::debug;
use test_harness::BeaconChainHarness;
use types::ChainSpec;

#[test]
fn it_can_build_on_genesis_block() {
    Builder::from_env(Env::default().default_filter_or("info")).init();

    let spec = ChainSpec::few_validators();
    let validator_count = 8;

    let mut harness = BeaconChainHarness::new(spec, validator_count as usize, None, true);

    harness.advance_chain_with_block();
}

#[test]
#[ignore]
fn it_can_produce_past_first_epoch_boundary() {
    Builder::from_env(Env::default().default_filter_or("info")).init();

    let spec = ChainSpec::few_validators();
    let validator_count = 8;

    debug!("Starting harness build...");

    let mut harness = BeaconChainHarness::new(spec, validator_count, None, true);

    debug!("Harness built, tests starting..");

    let blocks = harness.spec.slots_per_epoch * 2 + 1;

    for i in 0..blocks {
        harness.advance_chain_with_block();
        debug!("Produced block {}/{}.", i + 1, blocks);
    }

    harness.run_fork_choice();

    let dump = harness.chain_dump().expect("Chain dump failed.");

    assert_eq!(dump.len() as u64, blocks + 1); // + 1 for genesis block.
}
