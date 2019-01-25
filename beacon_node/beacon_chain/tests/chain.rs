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
}
