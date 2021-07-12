use clap::ArgMatches;
use eth2_network_config::Eth2NetworkConfig;
use ssz::Encode;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use types::{BeaconState, EthSpec};

pub fn run<T: EthSpec>(testnet_dir: PathBuf, matches: &ArgMatches) -> Result<(), String> {
    let path = matches
        .value_of("ssz-state")
        .ok_or("ssz-state not specified")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Unable to parse ssz-state: {}", e))?;

    let genesis_time = matches
        .value_of("genesis-time")
        .ok_or("genesis-time not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Unable to parse genesis-time: {}", e))?;

    let eth2_network_config = Eth2NetworkConfig::load(testnet_dir)?;
    let spec = &eth2_network_config.chain_spec::<T>()?;

    let mut state: BeaconState<T> = {
        let mut file = File::open(&path).map_err(|e| format!("Unable to open file: {}", e))?;

        let mut ssz = vec![];

        file.read_to_end(&mut ssz)
            .map_err(|e| format!("Unable to read file: {}", e))?;

        BeaconState::from_ssz_bytes(&ssz, spec)
            .map_err(|e| format!("Unable to decode SSZ: {:?}", e))?
    };

    *state.genesis_time_mut() = genesis_time;

    let mut file = File::create(path).map_err(|e| format!("Unable to create file: {}", e))?;

    file.write_all(&state.as_ssz_bytes())
        .map_err(|e| format!("Unable to write to file: {}", e))?;

    Ok(())
}
