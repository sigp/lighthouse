use clap::ArgMatches;
use clap_utils::parse_required;
use eth2_network_config::Eth2NetworkConfig;
use ssz::Decode;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;
use store::config::StoreConfig;
use store::hdiff::{HDiff, HDiffBuffer};
use tracing_subscriber::fmt::format::FmtSpan;
use types::{BeaconState, EthSpec};

pub fn run<E: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = &network_config
        .chain_spec::<E>()
        .map_err(|e| format!("Unable to get chain spec: {:?}", e))?;

    let state_path: PathBuf = parse_required(matches, "state-path")?;
    let hdiff_path: PathBuf = parse_required(matches, "hdiff-path")?;

    let state_bytes = read_file(&state_path)?;
    let hdiff_bytes = read_file(&hdiff_path)?;

    // Decode BeaconState from SSZ
    let t = Instant::now();
    let state = BeaconState::<E>::from_ssz_bytes(&state_bytes, spec)
        .map_err(|e| format!("Failed to decode BeaconState: {:?}", e))?;
    let state_decode_time = t.elapsed();
    println!("BeaconState SSZ decode: {:?}", state_decode_time);

    // Decode HDiff from SSZ
    let t = Instant::now();
    let hdiff = HDiff::from_ssz_bytes(&hdiff_bytes)
        .map_err(|e| format!("Failed to decode HDiff: {:?}", e))?;
    let hdiff_decode_time = t.elapsed();
    println!("HDiff SSZ decode: {:?}", hdiff_decode_time);

    print_hdiff_sizes(&hdiff);

    // Convert BeaconState to HDiffBuffer
    let t = Instant::now();
    let mut buffer = HDiffBuffer::from_state(state);
    let to_buffer_time = t.elapsed();
    println!("BeaconState -> HDiffBuffer: {:?}", to_buffer_time);

    // Apply the diff. Install a scoped subscriber so the per-component spans emitted inside
    // `HDiff::apply` are printed with their busy/idle timings. Scoped with `set_default` so we
    // don't stomp on the global lcli logger.
    let timing_subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_span_events(FmtSpan::CLOSE)
        .with_max_level(tracing::Level::DEBUG)
        .finish();

    let config = StoreConfig::default();
    let t = Instant::now();
    let apply_result = tracing::subscriber::with_default(timing_subscriber, || {
        hdiff.apply(&mut buffer, &config)
    });
    apply_result.map_err(|e| format!("Failed to apply HDiff: {:?}", e))?;
    let apply_time = t.elapsed();
    println!("HDiff apply: {:?}", apply_time);

    // Convert HDiffBuffer back to BeaconState
    let t = Instant::now();
    let _result_state: BeaconState<E> = buffer
        .as_state(spec)
        .map_err(|e| format!("Failed to convert HDiffBuffer to BeaconState: {:?}", e))?;
    let from_buffer_time = t.elapsed();
    println!("HDiffBuffer -> BeaconState: {:?}", from_buffer_time);

    println!("---");
    println!(
        "Total (excluding file I/O): {:?}",
        state_decode_time + hdiff_decode_time + to_buffer_time + apply_time + from_buffer_time
    );

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
