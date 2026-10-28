//! Expected periods are derived from the mainnet preset.
#![cfg(not(debug_assertions))]

use beacon_chain::{
    ChainConfig,
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
};
use bls::Keypair;
use std::sync::LazyLock;
use types::{ChainSpec, DEFAULT_PRE_ELECTRA_WS_PERIOD, EthSpec, ForkName, Spec};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 48;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn get_harness_with_spec(
    validator_count: usize,
    spec: &ChainSpec,
) -> BeaconChainHarness<EphemeralHarnessType<Spec>> {
    let chain_config = ChainConfig {
        archive: true,
        ..Default::default()
    };
    let harness = BeaconChainHarness::builder(Spec::default())
        .spec(spec.clone().into())
        .chain_config(chain_config)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

#[tokio::test]
async fn test_compute_weak_subjectivity_period() {
    type E = Spec;
    let expected_ws_period_pre_electra = DEFAULT_PRE_ELECTRA_WS_PERIOD;
    let expected_ws_period_post_electra = 256;

    // test Base variant
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);
    let head_state = harness.get_current_state();

    let calculated_ws_period = head_state.compute_weak_subjectivity_period(&spec).unwrap();

    assert_eq!(calculated_ws_period, expected_ws_period_pre_electra);

    // test Electra variant
    let spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);
    let head_state = harness.get_current_state();

    let calculated_ws_period = head_state.compute_weak_subjectivity_period(&spec).unwrap();

    assert_eq!(calculated_ws_period, expected_ws_period_post_electra);
}
