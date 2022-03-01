/// This library provides integration testing between Lighthouse and other execution engines.
///
/// See the `tests/tests.rs` file to run tests.
mod execution_engine;
mod genesis_json;
mod test_rig;

pub use execution_engine::Geth;
pub use test_rig::TestRig;

/// Set to `false` to send logs to the console during tests. Logs are useful when debugging.
const SUPPRESS_LOGS: bool = true;
