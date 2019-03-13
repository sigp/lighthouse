#![cfg(test)]
use crate::per_epoch_processing;
use env_logger::{Builder, Env};
use types::test_utils::TestingBeaconStateBuilder;
use types::*;

#[test]
fn runs_without_error() {
    Builder::from_env(Env::default().default_filter_or("error")).init();

    let spec = ChainSpec::few_validators();

    let mut builder = TestingBeaconStateBuilder::from_deterministic_keypairs(8, &spec);

    let target_slot = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
    builder.teleport_to_slot(target_slot, &spec);

    let (mut state, _keypairs) = builder.build();

    per_epoch_processing(&mut state, &spec).unwrap();
}
