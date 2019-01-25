use self::utils::TestRig;
use types::ChainSpec;

mod utils;

#[test]
fn it_can_produce_blocks() {
    let validator_count = 2;
    let blocks = 3;

    let mut rig = TestRig::new(ChainSpec::foundation(), validator_count);
    for _ in 0..blocks {
        rig.produce_next_slot();
    }
    let dump = rig.chain_dump().expect("Chain dump failed.");

    assert_eq!(dump.len(), blocks + 1); // + 1 for genesis block.

    rig.dump_to_file("/tmp/chaindump.json".to_string(), &dump);
}
