#![cfg(test)]
use crate::EpochProcessable;
use env_logger::{Builder, Env};
use types::beacon_state::BeaconStateBuilder;
use types::*;

#[test]
fn runs_without_error() {
    Builder::from_env(Env::default().default_filter_or("error")).init();

    let mut builder = BeaconStateBuilder::new(8);
    builder.spec = ChainSpec::few_validators();

    builder.build().unwrap();
    builder.teleport_to_end_of_epoch(builder.spec.genesis_epoch + 4);

    let mut state = builder.cloned_state();

    let spec = &builder.spec;
    state.per_epoch_processing(spec).unwrap();
}
