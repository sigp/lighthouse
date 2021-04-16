#![cfg(test)]
use crate::per_epoch_processing::process_epoch;
use beacon_chain::store::StoreConfig;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::types::{EthSpec, MinimalEthSpec};
use bls::Hash256;
use env_logger::{Builder, Env};
use types::Slot;

#[test]
fn runs_without_error() {
    Builder::from_env(Env::default().default_filter_or("error")).init();

    let harness = BeaconChainHarness::new_with_store_config(
        MinimalEthSpec,
        types::test_utils::generate_deterministic_keypairs(8),
        StoreConfig::default(),
    );
    harness.advance_slot();

    let spec = MinimalEthSpec::default_spec();
    let target_slot =
        (MinimalEthSpec::genesis_epoch() + 4).end_slot(MinimalEthSpec::slots_per_epoch());

    let mut state = harness.get_current_state();
    harness.add_attested_blocks_at_slots(
        state,
        Hash256::zero(),
        (1..target_slot.as_u64())
            .map(Slot::new)
            .collect::<Vec<_>>()
            .as_slice(),
        (0..8).collect::<Vec<_>>().as_slice(),
    );
    let mut new_head_state = harness.get_current_state();

    process_epoch(&mut new_head_state, &spec).unwrap();
}
