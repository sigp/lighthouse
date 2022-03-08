/// This binary runs integration tests between Lighthouse and execution engines.
///
/// It will first attempt to build any supported integration clients, then it will run tests.
///
/// A return code of `0` indicates the tests succeeded.
mod build_geth;
mod execution_engine;
mod genesis_json;
mod test_rig;

use execution_engine::Geth;
use test_rig::TestRig;

/// Set to `false` to send logs to the console during tests. Logs are useful when debugging.
const SUPPRESS_LOGS: bool = false;

fn main() {
    if cfg!(windows) {
        panic!("windows is not supported, only linux");
    }

    test_geth()
}

fn test_geth() {
    build_geth::build();
    TestRig::new(Geth).perform_tests_blocking();
}
