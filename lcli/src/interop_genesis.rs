use clap::ArgMatches;
use clap_utils::parse_ssz_optional;
use environment::Environment;
use eth2_network_config::Eth2NetworkConfig;
use genesis::interop_genesis_state;
use ssz::Encode;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{test_utils::generate_deterministic_keypairs, EthSpec, Hash256};

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let validator_count = matches
        .value_of("validator-count")
        .ok_or("validator-count not specified")?
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
        .ok_or(())
        .and_then(|dir| dir.parse::<PathBuf>().map_err(|_| ()))
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|home| home.join(directory::DEFAULT_ROOT_DIR).join("testnet"))
                .expect("should locate home directory")
        });

    let application_block_hash: Option<Hash256> =
        clap_utils::parse_optional(matches, "application-block-hash")?;
    let application_state_root: Option<Hash256> =
        clap_utils::parse_optional(matches, "application-state-root")?;

    let mut eth2_network_config = Eth2NetworkConfig::load(testnet_dir.clone())?;

    let mut spec = eth2_network_config
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

    if let Some(v) = parse_ssz_optional(matches, "genesis-fork-version")? {
        spec.genesis_fork_version = v;
    }

    let keypairs = generate_deterministic_keypairs(validator_count);
    let mut genesis_state = interop_genesis_state::<T>(&keypairs, genesis_time, &spec)?;

    if let Some(v) = application_block_hash {
        println!("state.application_block_hash = {:?}", v);
        genesis_state.application_block_hash = v;
    }

    if let Some(v) = application_state_root {
        genesis_state.application_state_root = v;
    }

    eth2_network_config.genesis_state_bytes = Some(genesis_state.as_ssz_bytes());
    eth2_network_config.force_write_to_file(testnet_dir)?;

    Ok(())
}
