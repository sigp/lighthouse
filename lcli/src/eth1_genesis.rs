use clap::ArgMatches;
use environment::Environment;
use eth2_network_config::Eth2NetworkConfig;
use genesis::{Eth1Config, Eth1GenesisService};
use sensitive_url::SensitiveUrl;
use ssz::Encode;
use std::cmp::max;
use std::path::PathBuf;
use std::time::Duration;
use types::EthSpec;

/// Interval between polling the eth1 node for genesis information.
pub const ETH1_GENESIS_UPDATE_INTERVAL: Duration = Duration::from_millis(7_000);

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches<'_>) -> Result<(), String> {
    let endpoints = matches
        .value_of("eth1-endpoint")
        .map(|e| {
            warn!("The --eth1-endpoint flag is deprecated. Please use --eth1-endpoints instead");
            vec![String::from(e)]
        })
        .or_else(|| {
            matches
                .value_of("eth1-endpoints")
                .map(|s| s.split(',').map(String::from).collect())
        });

    let testnet_dir = matches
        .value_of("testnet-dir")
        .ok_or(())
        .and_then(|dir| dir.parse::<PathBuf>().map_err(|_| ()))
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|home| home.join(directory::DEFAULT_ROOT_DIR).join("testnet"))
                .expect("should locate home directory")
        });

    let mut eth2_network_config = Eth2NetworkConfig::load(testnet_dir.clone())?;

    let spec = eth2_network_config
        .yaml_config
        .as_ref()
        .ok_or("The testnet directory must contain a spec config")?
        .apply_to_chain_spec::<T>(&env.core_context().eth2_config.spec)
        .ok_or_else(|| {
            format!(
                "The loaded config is not compatible with the {} spec",
                &env.core_context().eth2_config.eth_spec_id
            )
        })?;

    let mut config = Eth1Config::default();
    if let Some(v) = endpoints.clone() {
        config.endpoints = v
            .iter()
            .map(|s| SensitiveUrl::parse(s))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("Unable to parse eth1 endpoint URL: {:?}", e))?;
    }
    config.deposit_contract_address = format!("{:?}", spec.deposit_contract_address);
    config.deposit_contract_deploy_block = eth2_network_config.deposit_contract_deploy_block;
    config.lowest_cached_block_number = eth2_network_config.deposit_contract_deploy_block;
    config.follow_distance = spec.eth1_follow_distance / 2;
    config.node_far_behind_seconds = max(5, config.follow_distance) * spec.seconds_per_eth1_block;

    let genesis_service =
        Eth1GenesisService::new(config, env.core_context().log().clone(), spec.clone());

    env.runtime().block_on(async {
        let _ = genesis_service
            .wait_for_genesis_state::<T>(ETH1_GENESIS_UPDATE_INTERVAL, spec)
            .await
            .map(move |genesis_state| {
                eth2_network_config.genesis_state_bytes = Some(genesis_state.as_ssz_bytes());
                eth2_network_config.force_write_to_file(testnet_dir)
            })
            .map_err(|e| format!("Failed to find genesis: {}", e))?;

        info!("Starting service to produce genesis BeaconState from eth1");
        info!("Connecting to eth1 http endpoints: {:?}", endpoints);

        Ok(())
    })
}
