use clap::ArgMatches;
use clap_utils::parse_optional;
use eth2::types::GenericResponse;
use proto_array::{core::ProtoArray, test_utils::ProtoAnalysis};
use std::fs::File;
use std::path::PathBuf;
use types::*;

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let json_file_path: Option<PathBuf> = parse_optional(matches, "json-file")?;

    let proto_array: ProtoArray = if let Some(json_file_path) = json_file_path {
        let mut file = File::open(&json_file_path)
            .map_err(|e| format!("Failed to open {:?}: {:?}", json_file_path, e))?;
        serde_json::from_reader::<_, GenericResponse<_>>(&mut file)
            .map_err(|e| format!("Failed to parse JSON in {:?}: {:?}", json_file_path, e))?
            .data
    } else {
        return Err("No proto array JSON provided. Try --json-file.".into());
    };

    let proto_analysis = ProtoAnalysis::new::<T>(&proto_array)
        .map_err(|e| format!("Unable to analyze proto array: {:?}", e))?;

    dbg!(proto_analysis);

    Ok(())
}
