#![cfg(test)]
use crate::per_epoch_processing;
use benching_utils::BeaconStateBencher;
use env_logger::{Builder, Env};
use types::*;

#[test]
fn runs_without_error() {
    Builder::from_env(Env::default().default_filter_or("error")).init();

    let spec = ChainSpec::few_validators();

    let mut builder = BeaconStateBencher::new(8, &spec);
    builder.teleport_to_end_of_epoch(spec.genesis_epoch + 4, &spec);
    let mut state = builder.build();

    per_epoch_processing(&mut state, &spec).unwrap();
}
