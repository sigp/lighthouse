use test_harness::TestRig;
use types::ChainSpec;

#[test]
fn it_can_build_on_genesis_block() {
    let validator_count = 2;
    let mut rig = TestRig::new(ChainSpec::foundation(), validator_count);

    rig.advance_chain_with_block();
}

#[test]
#[ignore]
fn it_can_produce_past_first_epoch_boundary() {
    let validator_count = 2;
    let mut rig = TestRig::new(ChainSpec::foundation(), validator_count);

    let blocks = rig.spec.epoch_length + 1;

    for _ in 0..blocks {
        rig.advance_chain_with_block();
    }
    let dump = rig.chain_dump().expect("Chain dump failed.");

    assert_eq!(dump.len() as u64, blocks + 1); // + 1 for genesis block.

    rig.dump_to_file("/tmp/chaindump.json".to_string(), &dump);
}
