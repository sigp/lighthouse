use clap::ArgMatches;
use environment::Environment;
use eth2_testnet_config::Eth2TestnetConfig;
use futures::Future;
use genesis::{Eth1Config, Eth1GenesisService};
use std::path::PathBuf;
use std::time::Duration;
use types::EthSpec;

/// Interval between polling the eth1 node for genesis information.
pub const ETH1_GENESIS_UPDATE_INTERVAL: Duration = Duration::from_millis(7_000);

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

    let mut eth2_testnet_config: Eth2TestnetConfig<T> =
        Eth2TestnetConfig::load(testnet_dir.clone())?;

    let spec = eth2_testnet_config
        .yaml_config
        .as_ref()
        .ok_or_else(|| "The testnet directory must contain a spec config".to_string())?
        .apply_to_chain_spec::<T>(&env.core_context().eth2_config.spec)
        .ok_or_else(|| {
            format!(
                "The loaded config is not compatible with the {} spec",
                &env.core_context().eth2_config.spec_constants
            )
        })?;

    let mut config = Eth1Config::default();
    config.endpoint = endpoint.to_string();
    config.deposit_contract_address = eth2_testnet_config.deposit_contract_address.clone();
    config.deposit_contract_deploy_block = eth2_testnet_config.deposit_contract_deploy_block;
    config.lowest_cached_block_number = eth2_testnet_config.deposit_contract_deploy_block;
    config.follow_distance = spec.eth1_follow_distance / 2;

    let genesis_service = Eth1GenesisService::new(config, env.core_context().log.clone());

    let future = genesis_service
        .wait_for_genesis_state(ETH1_GENESIS_UPDATE_INTERVAL, spec)
        .map(move |genesis_state| {
            eth2_testnet_config.genesis_state = Some(genesis_state);
            eth2_testnet_config.force_write_to_file(testnet_dir)
        });

    info!("Starting service to produce genesis BeaconState from eth1");
    info!("Connecting to eth1 http endpoint: {}", endpoint);

    env.runtime()
        .block_on(future)
        .map_err(|e| format!("Failed to find genesis: {}", e))??;

    Ok(())
}
