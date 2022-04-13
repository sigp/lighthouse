/// This binary runs integration tests between Lighthouse and execution engines.
///
/// It will first attempt to build any supported integration clients, then it will run tests.
///
/// A return code of `0` indicates the tests succeeded.
mod build_utils;
mod execution_engine;
mod genesis_json;
mod geth;
mod nethermind;
mod test_rig;

use geth::GethEngine;
use test_rig::TestRig;
use types::MainnetEthSpec;

/// Set to `false` to send logs to the console during tests. Logs are useful when debugging.
const SUPPRESS_LOGS: bool = true;

fn main() {
    if cfg!(windows) {
        panic!("windows is not supported, only linux");
    }

    test_geth();
    test_nethermind();
}

fn test_geth() {
    let test_dir = build_utils::prepare_dir();
    geth::build(&test_dir);
    let rig: TestRig<_, MainnetEthSpec> = TestRig::new(GethEngine);
    rig.perform_tests_blocking();
}

fn test_nethermind() {
    let test_dir = build_utils::prepare_dir();
    nethermind::build(&test_dir);
    let rig: TestRig<_, MainnetEthSpec> = TestRig::new(GethEngine);
    rig.perform_tests_blocking();
}
