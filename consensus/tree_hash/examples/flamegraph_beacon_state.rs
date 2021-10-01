use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use types::{BeaconState, EthSpec, MainnetEthSpec};

const TREE_HASH_LOOPS: usize = 1_000;
const VALIDATOR_COUNT: usize = 1_000;

fn get_harness<T: EthSpec>() -> BeaconChainHarness<EphemeralHarnessType<T>> {
    let harness = BeaconChainHarness::builder(T::default())
        .default_spec()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .build();

    harness.advance_slot();

    harness
}

fn build_state<T: EthSpec>() -> BeaconState<T> {
    let state = get_harness::<T>().chain.head_beacon_state().unwrap();

    assert_eq!(state.as_base().unwrap().validators.len(), VALIDATOR_COUNT);
    assert_eq!(state.as_base().unwrap().balances.len(), VALIDATOR_COUNT);
    assert!(state
        .as_base()
        .unwrap()
        .previous_epoch_attestations
        .is_empty());
    assert!(state
        .as_base()
        .unwrap()
        .current_epoch_attestations
        .is_empty());
    assert!(state.as_base().unwrap().eth1_data_votes.is_empty());
    assert!(state.as_base().unwrap().historical_roots.is_empty());

    state
}

fn main() {
    let state = build_state::<MainnetEthSpec>();

    // This vec is an attempt to ensure the compiler doesn't optimize-out the hashing.
    let mut vec = Vec::with_capacity(TREE_HASH_LOOPS);

    for _ in 0..TREE_HASH_LOOPS {
        let root = state.canonical_root();
        vec.push(root[0]);
    }
}
