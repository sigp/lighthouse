use clap::ArgMatches;
use clap_utils::parse_ssz_optional;
use eth2_network_config::Eth2NetworkConfig;
use genesis::{interop_genesis_state, DEFAULT_ETH1_BLOCK_HASH};
use ssz::Encode;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{test_utils::generate_deterministic_keypairs, EthSpec, Hash256};

pub fn run<E: EthSpec>(testnet_dir: PathBuf, matches: &ArgMatches) -> Result<(), String> {
    let validator_count = matches
        .get_one::<String>("validator-count")
        .ok_or("validator-count not specified")?
        .parse::<usize>()
        .map_err(|e| format!("Unable to parse validator-count: {}", e))?;

    let genesis_time = if let Some(genesis_time) = matches.get_one::<String>("genesis-time") {
        genesis_time
            .parse::<u64>()
            .map_err(|e| format!("Unable to parse genesis-time: {}", e))?
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Unable to get time: {:?}", e))?
            .as_secs()
    };

    let mut eth2_network_config = Eth2NetworkConfig::load(testnet_dir.clone())?;

    let mut spec = eth2_network_config.chain_spec::<E>()?;

    if let Some(v) = parse_ssz_optional(matches, "genesis-fork-version")? {
        spec.genesis_fork_version = v;
    }

    let keypairs = generate_deterministic_keypairs(validator_count);
    let genesis_state = interop_genesis_state::<E>(
        &keypairs,
        genesis_time,
        Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
        None,
        &spec,
    )?;

    eth2_network_config.genesis_state_bytes = Some(genesis_state.as_ssz_bytes().into());
    eth2_network_config.force_write_to_file(testnet_dir)?;

    Ok(())
}
