use clap::ArgMatches;
use serde::Serialize;
use ssz::Decode;
use types::{BeaconBlock, BeaconState, MinimalEthSpec};

pub fn run_parse_hex(matches: &ArgMatches) -> Result<(), String> {
    let type_str = matches
        .value_of("type")
        .ok_or_else(|| "No type supplied".to_string())?;
    let mut hex: String = matches
        .value_of("hex_ssz")
        .ok_or_else(|| "No hex ssz supplied".to_string())?
        .to_string();

    if hex.starts_with("0x") {
        hex = hex[2..].to_string();
    }

    let hex = hex::decode(&hex).map_err(|e| format!("Failed to parse hex: {:?}", e))?;

    info!("Using minimal spec");
    info!("Type: {:?}", type_str);

    match type_str {
        "block" => decode_and_print::<BeaconBlock<MinimalEthSpec>>(&hex)?,
        "state" => decode_and_print::<BeaconState<MinimalEthSpec>>(&hex)?,
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
