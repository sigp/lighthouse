use execution_engine_integration::{Geth, TestRig};

#[test]
fn geth() {
    TestRig::new(Geth).perform_tests_blocking()
}
