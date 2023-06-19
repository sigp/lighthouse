use crate::transition_blocks::load_from_ssz_with;
use clap::ArgMatches;
use clap_utils::parse_required;
use environment::Environment;
use std::path::PathBuf;
use store::hdiff::{HDiff, HDiffBuffer};
use types::{BeaconState, EthSpec};

pub fn run<T: EthSpec>(_env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let state1_path: PathBuf = parse_required(matches, "state1")?;
    let state2_path: PathBuf = parse_required(matches, "state2")?;
    let spec = &T::default_spec();

    let state1 = load_from_ssz_with(&state1_path, spec, BeaconState::<T>::from_ssz_bytes)?;
    let state2 = load_from_ssz_with(&state2_path, spec, BeaconState::<T>::from_ssz_bytes)?;

    let buffer1 = HDiffBuffer::from_state(state1.clone());
    let buffer2 = HDiffBuffer::from_state(state2.clone());

    let t = std::time::Instant::now();
    let diff = HDiff::compute(&buffer1, &buffer2).unwrap();
    let elapsed = t.elapsed();

    println!("Diff size");
    println!("- state: {} bytes", diff.state_diff_len());
    println!("- balances: {} bytes", diff.balances_diff_len());
    println!("Computation time: {}ms", elapsed.as_millis());

    // Re-apply.
    let mut recon_buffer = HDiffBuffer::from_state(state1);

    let t = std::time::Instant::now();
    diff.apply(&mut recon_buffer).unwrap();

    println!("Diff application time: {}ms", t.elapsed().as_millis());

    let recon = recon_buffer.into_state(spec).unwrap();

    assert_eq!(state2, recon);

    Ok(())
}
