use clap::ArgMatches;
use clap_utils;
use serde::Serialize;
use ssz::Decode;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use types::{BeaconState, EthSpec, SignedBeaconBlock};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let type_str = matches.value_of("type").ok_or("No type supplied")?;
    let path = clap_utils::parse_required::<PathBuf>(matches, "path")?;

    info!("Type: {:?}", type_str);

    let mut bytes = vec![];
    let mut file = File::open(&path).map_err(|e| format!("Unable to open {:?}: {}", path, e))?;
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read {:?}: {}", path, e))?;

    match type_str {
        "block" => decode_and_print::<SignedBeaconBlock<T>>(&bytes)?,
        "state" => decode_and_print::<BeaconState<T>>(&bytes)?,
        other => return Err(format!("Unknown type: {}", other)),
    };

    Ok(())
}

fn decode_and_print<T: Decode + Serialize>(bytes: &[u8]) -> Result<(), String> {
    let item = T::from_ssz_bytes(&bytes).map_err(|e| format!("Ssz decode failed: {:?}", e))?;

    println!(
        "{}",
        serde_yaml::to_string(&item)
            .map_err(|e| format!("Unable to write object to YAML: {:?}", e))?
    );

    Ok(())
}
