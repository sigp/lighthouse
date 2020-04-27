use clap::ArgMatches;
use environment::Environment;
use eth2_testnet_config::Eth2TestnetConfig;
use genesis::interop_genesis_state;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{test_utils::generate_deterministic_keypairs, EthSpec};

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let validator_count = matches
        .value_of("validator-count")
        .ok_or_else(|| "validator-count not specified")?
        .parse::<usize>()
        .map_err(|e| format!("Unable to parse validator-count: {}", e))?;

    let genesis_time = if let Some(genesis_time) = matches.value_of("genesis-time") {
        genesis_time
            .parse::<u64>()
            .map_err(|e| format!("Unable to parse genesis-time: {}", e))?
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Unable to get time: {:?}", e))?
            .as_secs()
    };

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

    let mut spec = eth2_testnet_config
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

    spec.genesis_fork_version = [1, 3, 3, 7];

    let keypairs = generate_deterministic_keypairs(validator_count);
    let genesis_state = interop_genesis_state(&keypairs, genesis_time, &spec)?;

    eth2_testnet_config.genesis_state = Some(genesis_state);
    eth2_testnet_config.force_write_to_file(testnet_dir)?;

    Ok(())
}
