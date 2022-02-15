use execution_engine::{ExecutionEngine, Geth};
use test_rig::TestRig;

mod execution_engine;
mod genesis_json;
mod test_rig;

fn main() {
    let geth_rig = TestRig::new(ExecutionEngine::new(Geth));
    geth_rig.perform_tests_blocking();
}
