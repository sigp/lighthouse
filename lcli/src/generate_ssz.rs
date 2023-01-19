use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use types::*;

#[derive(Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum SszType<T: EthSpec> {
    BaseState(BeaconStateBase<T>),
    AltairState(BeaconStateAltair<T>),
    BellatrixState(BeaconStateMerge<T>),
    BaseBlock(BeaconBlockBase<T>),
    AltairBlock(BeaconBlockAltair<T>),
    BellatrixBlock(BeaconBlockMerge<T>),
}

pub fn run_parse_json<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let file_path = Path::new(matches.value_of("file").ok_or("No file supplied")?);
    let output_path = Path::new(
        matches
            .value_of("output")
            .ok_or("No output file supplied")?,
    );

    let data = fs::read_to_string(file_path).expect("Unable to read file");

    let ssz_type: SszType<T> = serde_json::from_str(&data).unwrap_or_else(|_| {
        serde_yaml::from_str(&data)
            .map_err(|_| "Unable to parse as either JSON or YAML".to_string())
    })?;

    let bytes = match ssz_type {
        SszType::BaseState(bases) => bases.as_ssz_bytes(),
        SszType::AltairState(altairs) => altairs.as_ssz_bytes(),
        SszType::BellatrixState(bellatrixs) => bellatrixs.as_ssz_bytes(),
        SszType::BaseBlock(baseb) => baseb.as_ssz_bytes(),
        SszType::AltairBlock(altairb) => altairb.as_ssz_bytes(),
        SszType::BellatrixBlock(bellatrixb) => bellatrixb.as_ssz_bytes(),
    };

    let mut output =
        File::create(output_path).map_err(|e| format!("Error creating output file: {}", e))?;
    output
        .write_all(&bytes)
        .map_err(|e| format!("Error writing to output to file: {}", e))?;

    Ok(())
}
