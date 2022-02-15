use execution_engine_integration::{Geth, TestRig};

#[test]
fn geth() {
    let geth_rig = TestRig::new(Geth);
    geth_rig.perform_tests_blocking();
}
