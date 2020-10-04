use clap::ArgMatches;
use ssz::{Decode, Encode};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use types::{BeaconState, EthSpec};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let path = matches
        .value_of("ssz-state")
        .ok_or_else(|| "ssz-state not specified")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Unable to parse ssz-state: {}", e))?;

    let genesis_time = matches
        .value_of("genesis-time")
        .ok_or_else(|| "genesis-time not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Unable to parse genesis-time: {}", e))?;

    let mut state: BeaconState<T> = {
        let mut file = File::open(&path).map_err(|e| format!("Unable to open file: {}", e))?;

        let mut ssz = vec![];

        file.read_to_end(&mut ssz)
            .map_err(|e| format!("Unable to read file: {}", e))?;

        BeaconState::from_ssz_bytes(&ssz).map_err(|e| format!("Unable to decode SSZ: {:?}", e))?
    };

    state.genesis_time = genesis_time;

    let mut file = File::create(path).map_err(|e| format!("Unable to create file: {}", e))?;

    file.write_all(&state.as_ssz_bytes())
        .map_err(|e| format!("Unable to write to file: {}", e))?;

    Ok(())
}
