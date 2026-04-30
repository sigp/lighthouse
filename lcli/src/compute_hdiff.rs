use crate::apply_hdiff::{log_hdiff_sizes, read_file, with_timing};
use clap::ArgMatches;
use clap_utils::parse_required;
use eth2_network_config::Eth2NetworkConfig;
use ssz::Encode;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use store::config::StoreConfig;
use store::hdiff::{HDiff, HDiffBuffer};
use tracing::{debug_span, info};
use types::{BeaconState, ChainSpec, EthSpec};

pub fn run<E: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = &network_config
        .chain_spec::<E>()
        .map_err(|e| format!("Unable to get chain spec: {:?}", e))?;

    let source_path: PathBuf = parse_required(matches, "source-state-path")?;
    let target_path: PathBuf = parse_required(matches, "target-state-path")?;
    let output_path: PathBuf = parse_required(matches, "output-path")?;

    let source_bytes = read_file(&source_path)?;
    let target_bytes = read_file(&target_path)?;

    with_timing(|| run_inner::<E>(spec, source_bytes, target_bytes, output_path))
}

fn run_inner<E: EthSpec>(
    spec: &ChainSpec,
    source_bytes: Vec<u8>,
    target_bytes: Vec<u8>,
    output_path: PathBuf,
) -> Result<(), String> {
    let source_state = debug_span!("source_state_ssz_decode").in_scope(|| {
        BeaconState::<E>::from_ssz_bytes(&source_bytes, spec)
            .map_err(|e| format!("Failed to decode source BeaconState: {:?}", e))
    })?;

    let target_state = debug_span!("target_state_ssz_decode").in_scope(|| {
        BeaconState::<E>::from_ssz_bytes(&target_bytes, spec)
            .map_err(|e| format!("Failed to decode target BeaconState: {:?}", e))
    })?;

    let source_buffer = debug_span!("source_state_to_hdiff_buffer")
        .in_scope(|| HDiffBuffer::from_state(source_state));

    let target_buffer = debug_span!("target_state_to_hdiff_buffer")
        .in_scope(|| HDiffBuffer::from_state(target_state));

    let config = StoreConfig::default();
    let hdiff = debug_span!("hdiff_compute")
        .in_scope(|| HDiff::compute(&source_buffer, &target_buffer, &config))
        .map_err(|e| format!("Failed to compute HDiff: {:?}", e))?;

    let hdiff_bytes = debug_span!("hdiff_ssz_encode").in_scope(|| hdiff.as_ssz_bytes());

    let mut output_file = File::create(&output_path)
        .map_err(|e| format!("Unable to create output file {:?}: {:?}", output_path, e))?;
    output_file
        .write_all(&hdiff_bytes)
        .map_err(|e| format!("Unable to write output file {:?}: {:?}", output_path, e))?;

    log_hdiff_sizes(&hdiff);
    info!("");
    info!("Written to {}", output_path.display());

    Ok(())
}
