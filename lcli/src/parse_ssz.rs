use crate::helpers::parse_path;
use clap::ArgMatches;
use serde::Serialize;
use ssz::Decode;
use std::fs::File;
use std::io::Read;
use types::{EthSpec, SignedBeaconBlock};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let type_str = matches
        .value_of("type")
        .ok_or_else(|| "No type supplied".to_string())?;
    let path = parse_path(matches, "path")?;

    info!("Type: {:?}", type_str);

    let mut bytes = vec![];
    let mut file = File::open(&path).map_err(|e| format!("Unable to open {:?}: {}", path, e))?;
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read {:?}: {}", path, e))?;

    match type_str {
        "SignedBeaconBlock" => decode_and_print::<SignedBeaconBlock<T>>(&bytes)?,
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
