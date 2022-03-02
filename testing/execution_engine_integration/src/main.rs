/// This binary runs integration tests between Lighthouse and execution engines.
///
/// It will first attempt to build any supported integration clients, then it will run tests.
///
/// A return code of `0` indicates the tests succeeded.
mod build_geth;
mod execution_engine;
mod genesis_json;
mod test_rig;

/// Set to `false` to send logs to the console during tests. Logs are useful when debugging.
const SUPPRESS_LOGS: bool = false;

fn main() {
    run_tests()
}

#[cfg(not(target_family = "windows"))]
fn run_tests() {
    use execution_engine::Geth;
    use test_rig::TestRig;

    build_geth::build();

    TestRig::new(Geth).perform_tests_blocking();
}

#[cfg(target_family = "windows")]
fn run_tests() {
    // Tests are not supported on Windows. All the build scripts assume Linux at this point.
}
