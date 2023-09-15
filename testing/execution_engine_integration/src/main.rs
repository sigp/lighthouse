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
mod transactions;

use geth::GethEngine;
use nethermind::NethermindEngine;
use test_rig::TestRig;

/// Set to `false` to send logs to the console during tests. Logs are useful when debugging.
const SUPPRESS_LOGS: bool = false;

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
    TestRig::new(GethEngine).perform_tests_blocking();
}

fn test_nethermind() {
    let test_dir = build_utils::prepare_dir();
    nethermind::build(&test_dir);
    TestRig::new(NethermindEngine).perform_tests_blocking();
}
