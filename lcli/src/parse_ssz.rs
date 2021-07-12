use clap::ArgMatches;
use serde::Serialize;
use ssz::Decode;
use std::fs::File;
use std::io::Read;
use types::*;

pub fn run_parse_ssz<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let type_str = matches.value_of("type").ok_or("No type supplied")?;
    let filename = matches.value_of("ssz-file").ok_or("No file supplied")?;

    let mut bytes = vec![];
    let mut file =
        File::open(filename).map_err(|e| format!("Unable to open {}: {}", filename, e))?;
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read {}: {}", filename, e))?;

    info!("Using {} spec", T::spec_name());
    info!("Type: {:?}", type_str);

    match type_str {
        "block_base" => decode_and_print::<BeaconBlockBase<T>>(&bytes)?,
        "block_altair" => decode_and_print::<BeaconBlockAltair<T>>(&bytes)?,
        "state_base" => decode_and_print::<BeaconStateBase<T>>(&bytes)?,
        "state_altair" => decode_and_print::<BeaconStateAltair<T>>(&bytes)?,
        other => return Err(format!("Unknown type: {}", other)),
    };

    Ok(())
}

fn decode_and_print<T: Decode + Serialize>(bytes: &[u8]) -> Result<(), String> {
    let item = T::from_ssz_bytes(&bytes).map_err(|e| format!("SSZ decode failed: {:?}", e))?;

    println!(
        "{}",
        serde_yaml::to_string(&item)
            .map_err(|e| format!("Unable to write object to YAML: {:?}", e))?
    );

    Ok(())
}
