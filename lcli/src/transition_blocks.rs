use clap::ArgMatches;
use eth2_network_config::Eth2NetworkConfig;
use ssz::Encode;
use state_processing::{per_block_processing, per_slot_processing, BlockSignatureStrategy};
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use types::{BeaconState, ChainSpec, EthSpec, SignedBeaconBlock};

pub fn run_transition_blocks<T: EthSpec>(
    testnet_dir: PathBuf,
    matches: &ArgMatches,
) -> Result<(), String> {
    let pre_state_path = matches
        .value_of("pre-state")
        .ok_or("No pre-state file supplied")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse pre-state path: {}", e))?;

    let block_path = matches
        .value_of("block")
        .ok_or("No block file supplied")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse block path: {}", e))?;

    let output_path = matches
        .value_of("output")
        .ok_or("No output file supplied")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Failed to parse output path: {}", e))?;

    info!("Using {} spec", T::spec_name());
    info!("Pre-state path: {:?}", pre_state_path);
    info!("Block path: {:?}", block_path);

    let eth2_network_config = Eth2NetworkConfig::load(testnet_dir)?;
    let spec = &eth2_network_config.chain_spec::<T>()?;

    let pre_state: BeaconState<T> =
        load_from_ssz_with(&pre_state_path, spec, BeaconState::from_ssz_bytes)?;
    let block: SignedBeaconBlock<T> =
        load_from_ssz_with(&block_path, spec, SignedBeaconBlock::from_ssz_bytes)?;

    let post_state = do_transition(pre_state, block, spec)?;

    let mut output_file =
        File::create(output_path).map_err(|e| format!("Unable to create output file: {:?}", e))?;

    output_file
        .write_all(&post_state.as_ssz_bytes())
        .map_err(|e| format!("Unable to write to output file: {:?}", e))?;

    Ok(())
}

fn do_transition<T: EthSpec>(
    mut pre_state: BeaconState<T>,
    block: SignedBeaconBlock<T>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    pre_state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;

    // Transition the parent state to the block slot.
    for i in pre_state.slot().as_u64()..block.slot().as_u64() {
        per_slot_processing(&mut pre_state, None, spec)
            .map_err(|e| format!("Failed to advance slot on iteration {}: {:?}", i, e))?;
    }

    pre_state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;

    per_block_processing(
        &mut pre_state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        spec,
    )
    .map_err(|e| format!("State transition failed: {:?}", e))?;

    Ok(pre_state)
}

pub fn load_from_ssz_with<T>(
    path: &Path,
    spec: &ChainSpec,
    decoder: impl FnOnce(&[u8], &ChainSpec) -> Result<T, ssz::DecodeError>,
) -> Result<T, String> {
    let mut file =
        File::open(path).map_err(|e| format!("Unable to open file {:?}: {:?}", path, e))?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read from file {:?}: {:?}", path, e))?;
    decoder(&bytes, spec).map_err(|e| format!("Ssz decode failed: {:?}", e))
}
