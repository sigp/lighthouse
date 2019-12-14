// #![cfg(not(debug_assertions))]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType,
};
use store::iter::LeanReverseAncestorIter;
use types::{
    test_utils::generate_deterministic_keypairs, EthSpec, Hash256, MinimalEthSpec, Slot, Unsigned,
};

type E = MinimalEthSpec;

fn get_harness(validator_count: usize) -> BeaconChainHarness<HarnessType<MinimalEthSpec>> {
    let harness = BeaconChainHarness::new(
        MinimalEthSpec,
        generate_deterministic_keypairs(validator_count),
    );

    harness.advance_slot();

    harness
}

#[test]
fn lean_ancestor_iterators_genesis() {
    let harness = get_harness(24);

    let lengths = vec![
        <E as EthSpec>::SlotsPerHistoricalRoot::to_usize(),
        <E as EthSpec>::SlotsPerHistoricalRoot::to_usize() - 1,
        <E as EthSpec>::SlotsPerHistoricalRoot::to_usize() / 2,
        3,
        2,
        1,
    ];

    for len in lengths {
        lean_ancestor_iterators_checks(&harness, 0, len);
    }
}

#[test]
fn lean_ancestor_iterators_len_half_historical_roots() {
    lean_ancestor_iterators_test(<E as EthSpec>::SlotsPerHistoricalRoot::to_usize() / 2);
}

#[test]
fn lean_ancestor_iterators_len_1_times_historical_roots() {
    lean_ancestor_iterators_test(<E as EthSpec>::SlotsPerHistoricalRoot::to_usize());
}

#[test]
fn lean_ancestor_iterators_len_3_times_historical_roots() {
    lean_ancestor_iterators_test(<E as EthSpec>::SlotsPerHistoricalRoot::to_usize() * 3);
}

/// Run a test on the ancestor iterators given a chain of length `num_blocks_produced + 1`.
fn lean_ancestor_iterators_test(num_blocks_produced: usize) {
    let harness = get_harness(24);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        // No need to produce attestations for this test.
        AttestationStrategy::SomeValidators(vec![]),
    );

    let lengths = vec![
        <E as EthSpec>::SlotsPerHistoricalRoot::to_usize(),
        <E as EthSpec>::SlotsPerHistoricalRoot::to_usize() - 1,
        <E as EthSpec>::SlotsPerHistoricalRoot::to_usize() / 2,
        3,
        2,
        1,
    ];

    for len in lengths {
        lean_ancestor_iterators_checks(&harness, num_blocks_produced, len);
    }
}

/// Generate iterators and check them against the harness.
fn lean_ancestor_iterators_checks(
    harness: &BeaconChainHarness<HarnessType<MinimalEthSpec>>,
    num_blocks_produced: usize,
    len: usize,
) {
    let store = harness.chain.store.clone();
    let state = &harness.chain.head().beacon_state;

    let block_roots: Vec<(Hash256, Slot)> =
        LeanReverseAncestorIter::block_roots(store.clone(), state, len)
            .expect("should create iter")
            .collect();
    let state_roots: Vec<(Hash256, Slot)> =
        LeanReverseAncestorIter::state_roots(store.clone(), state, len)
            .expect("should create iter")
            .collect();

    assert_eq!(
        block_roots.len(),
        state_roots.len(),
        "should be an equal amount of block and state roots"
    );

    assert_eq!(
        block_roots.len(),
        num_blocks_produced as usize,
        "should contain all produced blocks"
    );

    if state.slot == 0 {
        // No need to run the following tests for the genesis case.
        return;
    }

    assert!(
        block_roots.iter().any(|(_root, slot)| *slot == 0),
        "should contain genesis block root"
    );
    assert!(
        state_roots.iter().any(|(_root, slot)| *slot == 0),
        "should contain genesis state root"
    );

    block_roots.windows(2).for_each(|x| {
        assert_eq!(
            x[1].1,
            x[0].1 - 1,
            "block root slots should be decreasing by one"
        )
    });
    state_roots.windows(2).for_each(|x| {
        assert_eq!(
            x[1].1,
            x[0].1 - 1,
            "state root slots should be decreasing by one"
        )
    });

    let head = &harness.chain.head();

    assert!(
        *block_roots.first().expect("should have some block roots")
            != (head.beacon_block_root, head.beacon_block.slot),
        "first block root and slot should not be for the head block"
    );

    assert!(
        *state_roots.first().expect("should have some state roots")
            != (head.beacon_state_root, head.beacon_state.slot),
        "first state root and slot should not be for the head state"
    );
}
