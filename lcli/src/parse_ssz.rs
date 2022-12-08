use clap::ArgMatches;
use clap_utils::parse_required;
use serde::Serialize;
use snap::raw::Decoder;
use ssz::Decode;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use types::*;

enum OutputFormat {
    Json,
    Yaml,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            _ => Err(format!("Invalid output format \"{}\"", s)),
        }
    }
}

pub fn run_parse_ssz<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let type_str = matches.value_of("type").ok_or("No type supplied")?;
    let filename = matches.value_of("ssz-file").ok_or("No file supplied")?;
    let format = parse_required(matches, "format")?;

    let bytes = if filename.ends_with("ssz_snappy") {
        let bytes = fs::read(filename).unwrap();
        let mut decoder = Decoder::new();
        decoder.decompress_vec(&bytes).unwrap()
    } else {
        let mut bytes = vec![];
        let mut file =
            File::open(filename).map_err(|e| format!("Unable to open {}: {}", filename, e))?;
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("Unable to read {}: {}", filename, e))?;
        bytes
    };

    info!("Using {} spec", T::spec_name());
    info!("Type: {:?}", type_str);

    match type_str {
        "signed_block_base" => decode_and_print::<SignedBeaconBlockBase<T>>(&bytes, format)?,
        "signed_block_altair" => decode_and_print::<SignedBeaconBlockAltair<T>>(&bytes, format)?,
        "signed_block_merge" => decode_and_print::<SignedBeaconBlockMerge<T>>(&bytes, format)?,
        "signed_block_capella" => decode_and_print::<SignedBeaconBlockCapella<T>>(&bytes, format)?,
        "signed_block_eip4844" => decode_and_print::<SignedBeaconBlockEip4844<T>>(&bytes, format)?,
        "block_base" => decode_and_print::<BeaconBlockBase<T>>(&bytes, format)?,
        "block_altair" => decode_and_print::<BeaconBlockAltair<T>>(&bytes, format)?,
        "block_merge" => decode_and_print::<BeaconBlockMerge<T>>(&bytes, format)?,
        "block_capella" => decode_and_print::<BeaconBlockCapella<T>>(&bytes, format)?,
        "block_eip4844" => decode_and_print::<BeaconBlockEip4844<T>>(&bytes, format)?,
        "state_base" => decode_and_print::<BeaconStateBase<T>>(&bytes, format)?,
        "state_altair" => decode_and_print::<BeaconStateAltair<T>>(&bytes, format)?,
        "state_merge" => decode_and_print::<BeaconStateMerge<T>>(&bytes, format)?,
        "state_capella" => decode_and_print::<BeaconStateCapella<T>>(&bytes, format)?,
        "state_eip4844" => decode_and_print::<BeaconStateEip4844<T>>(&bytes, format)?,
        other => return Err(format!("Unknown type: {}", other)),
    };

    Ok(())
}

fn decode_and_print<T: Decode + Serialize>(
    bytes: &[u8],
    output_format: OutputFormat,
) -> Result<(), String> {
    let item = T::from_ssz_bytes(bytes).map_err(|e| format!("SSZ decode failed: {:?}", e))?;

    match output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(&item)
                    .map_err(|e| format!("Unable to write object to JSON: {:?}", e))?
            );
        }
        OutputFormat::Yaml => {
            println!(
                "{}",
                serde_yaml::to_string(&item)
                    .map_err(|e| format!("Unable to write object to YAML: {:?}", e))?
            );
        }
    }

    Ok(())
}
