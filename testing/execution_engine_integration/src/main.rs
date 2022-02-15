/// This binary will run integration tests between Lighthouse and other execution engines.
///
/// If successful, the binary will exit with success (code 0). Any other return code indicates a
/// failure.
use execution_engine::Geth;
use test_rig::TestRig;

mod execution_engine;
mod genesis_json;
mod test_rig;

fn main() {
    let geth_rig = TestRig::new(Geth);
    geth_rig.perform_tests_blocking();
}
