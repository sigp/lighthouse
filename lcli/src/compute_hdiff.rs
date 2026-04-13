use clap::ArgMatches;
use clap_utils::parse_required;
use eth2_network_config::Eth2NetworkConfig;
use ssz::Encode;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;
use store::config::StoreConfig;
use store::hdiff::{HDiff, HDiffBuffer};
use types::{BeaconState, EthSpec};

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

    // Decode source BeaconState
    let t = Instant::now();
    let source_state = BeaconState::<E>::from_ssz_bytes(&source_bytes, spec)
        .map_err(|e| format!("Failed to decode source BeaconState: {:?}", e))?;
    println!("Source BeaconState SSZ decode: {:?}", t.elapsed());

    // Decode target BeaconState
    let t = Instant::now();
    let target_state = BeaconState::<E>::from_ssz_bytes(&target_bytes, spec)
        .map_err(|e| format!("Failed to decode target BeaconState: {:?}", e))?;
    println!("Target BeaconState SSZ decode: {:?}", t.elapsed());

    // Convert to HDiffBuffers
    let t = Instant::now();
    let source_buffer = HDiffBuffer::from_state(source_state);
    println!("Source BeaconState -> HDiffBuffer: {:?}", t.elapsed());

    let t = Instant::now();
    let target_buffer = HDiffBuffer::from_state(target_state);
    println!("Target BeaconState -> HDiffBuffer: {:?}", t.elapsed());

    // Compute diff
    let config = StoreConfig::default();
    let t = Instant::now();
    let hdiff = HDiff::compute(&source_buffer, &target_buffer, &config)
        .map_err(|e| format!("Failed to compute HDiff: {:?}", e))?;
    let compute_time = t.elapsed();
    println!("HDiff compute: {:?}", compute_time);

    print_hdiff_sizes(&hdiff);

    // Encode and write to file
    let t = Instant::now();
    let hdiff_bytes = hdiff.as_ssz_bytes();
    println!("HDiff SSZ encode: {:?}", t.elapsed());

    let mut output_file = File::create(&output_path)
        .map_err(|e| format!("Unable to create output file {:?}: {:?}", output_path, e))?;
    output_file
        .write_all(&hdiff_bytes)
        .map_err(|e| format!("Unable to write output file {:?}: {:?}", output_path, e))?;

    println!("Written to {}", output_path.display());

    Ok(())
}

fn print_hdiff_sizes(hdiff: &HDiff) {
    let sizes = hdiff.sizes();
    let labels = [
        "state_diff",
        "balances_diff",
        "inactivity_scores_diff",
        "validators_diff",
        "historical_roots",
        "historical_summaries",
    ];
    println!("HDiff component sizes:");
    for (label, size) in labels.iter().zip(sizes.iter()) {
        println!("  {}: {} bytes", label, size);
    }
    println!("  total: {} bytes", hdiff.size());
}

fn read_file(path: &PathBuf) -> Result<Vec<u8>, String> {
    let mut file =
        File::open(path).map_err(|e| format!("Unable to open file {:?}: {:?}", path, e))?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read file {:?}: {:?}", path, e))?;
    Ok(bytes)
}
