use test_harness::BeaconChainHarness;
use types::ChainSpec;

#[test]
fn it_can_build_on_genesis_block() {
    let validator_count = 10;
    let spec = ChainSpec::foundation();
    let mut harness = BeaconChainHarness::new(spec, validator_count);

    harness.advance_chain_with_block();
}

#[test]
#[ignore]
fn it_can_produce_past_first_epoch_boundary() {
    let validator_count = 100;
    let mut harness = BeaconChainHarness::new(ChainSpec::foundation(), validator_count);

    let blocks = harness.spec.epoch_length + 1;

    for _ in 0..blocks {
        harness.advance_chain_with_block();
    }
    let dump = harness.chain_dump().expect("Chain dump failed.");

    assert_eq!(dump.len() as u64, blocks + 1); // + 1 for genesis block.

    harness.dump_to_file("/tmp/chaindump.json".to_string(), &dump);
}
