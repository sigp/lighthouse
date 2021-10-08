//! Generic tests that make use of the (newer) `InteractiveApiTester`
use crate::common::*;
use eth2::types::DepositContractData;
use types::{EthSpec, MainnetEthSpec};

type E = MainnetEthSpec;

// Test that the deposit_contract endpoint returns the correct chain_id and address.
// Regression test for https://github.com/sigp/lighthouse/issues/2657
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_contract_custom_network() {
    let validator_count = 24;
    let mut spec = E::default_spec();

    // Rinkeby, which we don't use elsewhere.
    spec.deposit_chain_id = 4;
    spec.deposit_network_id = 4;
    // Arbitrary contract address.
    spec.deposit_contract_address = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();

    let tester = InteractiveTester::<E>::new(Some(spec.clone()), validator_count).await;
    let client = &tester.client;

    let result = client.get_config_deposit_contract().await.unwrap().data;

    let expected = DepositContractData {
        address: spec.deposit_contract_address,
        chain_id: spec.deposit_chain_id,
    };

    assert_eq!(result, expected);
}
