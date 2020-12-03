use crate::transition_blocks::load_from_ssz;
use clap::ArgMatches;
use ssz::Encode;
use state_processing::per_slot_processing;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use types::{BeaconState, EthSpec};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let pre_state_path = matches
        .value_of("pre-state")
        .ok_or("No pre-state file supplied")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse pre-state path: {}", e))?;

    let slots = matches
        .value_of("slots")
        .ok_or("No slots supplied")?
        .parse::<usize>()
        .map_err(|e| format!("Failed to parse slots: {}", e))?;

    let output_path = matches
        .value_of("output")
        .ok_or("No output file supplied")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse output path: {}", e))?;

    info!("Using {} spec", T::spec_name());
    info!("Pre-state path: {:?}", pre_state_path);
    info!("Slots: {:?}", slots);

    let mut state: BeaconState<T> = load_from_ssz(pre_state_path)?;

    let spec = &T::default_spec();

    state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;

    // Transition the parent state to the block slot.
    for i in 0..slots {
        per_slot_processing(&mut state, None, spec)
            .map_err(|e| format!("Failed to advance slot on iteration {}: {:?}", i, e))?;
    }

    let mut output_file =
        File::create(output_path).map_err(|e| format!("Unable to create output file: {:?}", e))?;

    output_file
        .write_all(&state.as_ssz_bytes())
        .map_err(|e| format!("Unable to write to output file: {:?}", e))?;

    Ok(())
}
