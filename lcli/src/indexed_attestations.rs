use clap::ArgMatches;
use clap_utils::parse_required;
use state_processing::common::get_indexed_attestation;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use types::*;

fn read_file_bytes(filename: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = vec![];
    let mut file = File::open(filename)
        .map_err(|e| format!("Unable to open {}: {}", filename.display(), e))?;
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read {}: {}", filename.display(), e))?;
    Ok(bytes)
}

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let spec = &T::default_spec();

    let state_file: PathBuf = parse_required(matches, "state")?;
    let attestations_file: PathBuf = parse_required(matches, "attestations")?;

    let mut state = BeaconState::<T>::from_ssz_bytes(&read_file_bytes(&state_file)?, spec)
        .map_err(|e| format!("Invalid state: {:?}", e))?;
    state
        .build_all_committee_caches(spec)
        .map_err(|e| format!("{:?}", e))?;

    let attestations: Vec<Attestation<T>> =
        serde_json::from_slice(&read_file_bytes(&attestations_file)?)
            .map_err(|e| format!("Invalid attestation list: {:?}", e))?;

    let indexed_attestations = attestations
        .into_iter()
        .map(|att| {
            let committee = state.get_beacon_committee(att.data.slot, att.data.index)?;
            get_indexed_attestation(committee.committee, &att)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Error constructing indexed attestation: {:?}", e))?;

    let string_output = serde_json::to_string_pretty(&indexed_attestations)
        .map_err(|e| format!("Unable to convert to JSON: {:?}", e))?;
    println!("{}", string_output);

    Ok(())
}
