use self::utils::TestRig;
use types::ChainSpec;

mod utils;

#[test]
#[ignore]
fn it_can_produce_blocks() {
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
