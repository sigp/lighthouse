use clap::ArgMatches;
use environment::Environment;
use eth2_testnet::Eth2TestnetDir;
use futures::Future;
use genesis::{Eth1Config, Eth1GenesisService};
use std::path::PathBuf;
use std::time::Duration;
use types::{EthSpec, Fork};

/// Interval between polling the eth1 node for genesis information.
pub const ETH1_GENESIS_UPDATE_INTERVAL_MILLIS: u64 = 7_000;
pub const SECONDS_PER_ETH1_BLOCK: u64 = 15;

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let endpoint = matches
        .value_of("eth1-endpoint")
        .ok_or_else(|| "eth1-endpoint not specified")?;

    let testnet_dir = matches
        .value_of("testnet-dir")
        .ok_or_else(|| ())
        .and_then(|dir| dir.parse::<PathBuf>().map_err(|_| ()))
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|home| home.join(".lighthouse").join("testnet"))
                .expect("should locate home directory")
        });

    let mut eth2_testnet_dir: Eth2TestnetDir<T> = Eth2TestnetDir::load(testnet_dir.clone())?;

    let mut config = Eth1Config::default();
    config.endpoint = endpoint.to_string();
    config.deposit_contract_address = eth2_testnet_dir.deposit_contract_address.clone();
    config.deposit_contract_deploy_block = eth2_testnet_dir.deposit_contract_deploy_block;
    config.lowest_cached_block_number = eth2_testnet_dir.deposit_contract_deploy_block;

    let genesis_service = Eth1GenesisService::new(config, env.core_context().log.clone());
    let mut spec = env.core_context().eth2_config.spec.clone();

    spec.min_genesis_time = eth2_testnet_dir.min_genesis_time;

    spec.min_deposit_amount = 100;
    spec.max_effective_balance = 3_200_000_000;
    spec.ejection_balance = 1_600_000_000;
    spec.effective_balance_increment = 100_000_000;

    // Note: these are hard-coded hacky values. This should be fixed when we can load a testnet
    // dir from the `Eth2TestnetDir`.
    spec.eth1_follow_distance = 16;
    spec.seconds_per_day = SECONDS_PER_ETH1_BLOCK * spec.eth1_follow_distance * 2;

    let future = genesis_service
        .wait_for_genesis_state(
            Duration::from_millis(ETH1_GENESIS_UPDATE_INTERVAL_MILLIS),
            spec,
        )
        .map(move |genesis_state| {
            eth2_testnet_dir.genesis_state = Some(genesis_state);
            eth2_testnet_dir.force_write_to_file(testnet_dir)
        });

    env.runtime()
        .block_on(future)
        .map_err(|e| format!("Failed to find genesis: {}", e))??;

    Ok(())
}
