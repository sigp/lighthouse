// #![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType,
};
use types::{EthSpec, Keypair, MinimalEthSpec};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness(validator_count: usize) -> BeaconChainHarness<HarnessType<MinimalEthSpec>> {
    let harness = BeaconChainHarness::new(MinimalEthSpec, KEYPAIRS[0..validator_count].to_vec());

    harness.advance_slot();

    harness
}

#[test]
fn import_chain_segment() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness_a = get_harness(VALIDATOR_COUNT);
    let harness_b = get_harness(VALIDATOR_COUNT);

    harness_a.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let blocks = harness_a
        .chain
        .chain_dump()
        .expect("should dump chain")
        .into_iter()
        .skip(1)
        .map(|snapshot| snapshot.beacon_block)
        .collect::<Vec<_>>();

    harness_b.chain.slot_clock.set_slot(
        harness_a
            .chain
            .slot()
            .expect("harness_a should have slot")
            .as_u64(),
    );

    harness_b
        .chain
        .import_chain_segment(blocks)
        .expect("should import chain segement");

    harness_b
        .chain
        .fork_choice()
        .expect("should run fork choice");

    assert_eq!(
        harness_a
            .chain
            .head_info()
            .expect("should get harness a head"),
        harness_b
            .chain
            .head_info()
            .expect("should get harness b head"),
        "harnesses should have equal heads"
    );
}
