use beacon_chain::test_utils::BeaconChainHarness;
use types::{EthSpec, MainnetEthSpec};

const VALIDATOR_COUNT: usize = 32;

type E = MainnetEthSpec;

#[test]
fn basic_merge() {
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .fresh_ephemeral_store()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .build();
}
