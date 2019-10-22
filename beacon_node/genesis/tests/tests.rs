//! NOTE: These tests will not pass unless ganache-cli is running on `ENDPOINT` (see below).
//!
//! You can start a suitable instance using the `ganache_test_node.sh` script in the `scripts`
//! dir in the root of the `lighthouse` repo.
#![cfg(test)]
use environment::{Environment, EnvironmentBuilder};
use eth1_test_rig::{DelayThenDeposit, DepositContract};
use futures::Future;
use genesis::{Eth1Config, Eth1GenesisService};
use state_processing::is_valid_genesis_state;
use std::time::Duration;
use types::{test_utils::generate_deterministic_keypair, Hash256, MinimalEthSpec};

const ENDPOINT: &str = "http://localhost:8545";

pub fn new_env() -> Environment<MinimalEthSpec> {
    EnvironmentBuilder::minimal()
        .tokio_runtime()
        .expect("should start tokio runtime")
        .null_logger()
        .expect("should start null logger")
        .build()
        .expect("should build env")
}

#[test]
fn basic() {
    let mut env = new_env();
    let log = env.core_log();
    let mut spec = env.eth2_config().spec.clone();
    let runtime = env.runtime();

    let deposit_contract =
        DepositContract::deploy(ENDPOINT).expect("should deploy deposit contract");
    let mut utils = deposit_contract.unsafe_blocking_utils();

    let now = utils.block_number();

    let service = Eth1GenesisService::new(
        Eth1Config {
            endpoint: ENDPOINT.to_string(),
            deposit_contract_address: deposit_contract.address(),
            deposit_contract_deploy_block: now,
            lowest_cached_block_number: now,
            follow_distance: 0,
            block_cache_truncation: None,
            ..Eth1Config::default()
        },
        log,
    );

    // NOTE: this test is sensitive to the response speed of the external web3 server. If
    // you're experiencing failures, try increasing the update_interval.
    let update_interval = Duration::from_millis(500);

    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = 8;

    let deposits = (0..spec.min_genesis_active_validator_count + 2)
        .into_iter()
        .map(|i| {
            deposit_contract.deposit_helper::<MinimalEthSpec>(
                generate_deterministic_keypair(i as usize),
                Hash256::from_low_u64_le(i),
                32_000_000_000,
            )
        })
        .map(|deposit| DelayThenDeposit {
            delay: Duration::from_secs(0),
            deposit,
        })
        .collect::<Vec<_>>();

    let deposit_future = deposit_contract.deposit_multiple(deposits.clone());

    let wait_future =
        service.wait_for_genesis_state::<MinimalEthSpec>(update_interval, spec.clone());

    let state = runtime
        .block_on(deposit_future.join(wait_future))
        .map(|(_, state)| state)
        .expect("should finish waiting for genesis");

    // Note: using ganache these deposits are 1-per-block, therefore we know there should only be
    // the minimum number of validators.
    assert_eq!(
        state.validators.len(),
        spec.min_genesis_active_validator_count as usize,
        "should have expected validator count"
    );

    assert!(state.genesis_time > 0, "should have some genesis time");

    assert!(
        is_valid_genesis_state(&state, &spec),
        "should be valid genesis state"
    );

    assert!(
        is_valid_genesis_state(&state, &spec),
        "should be valid genesis state"
    );
}
