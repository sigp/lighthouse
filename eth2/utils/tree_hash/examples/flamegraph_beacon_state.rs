use types::test_utils::TestingBeaconStateBuilder;
use types::{BeaconState, EthSpec, MainnetEthSpec};

const TREE_HASH_LOOPS: usize = 1_000;
const VALIDATOR_COUNT: usize = 1_000;

fn build_state<T: EthSpec>(validator_count: usize) -> BeaconState<T> {
    let (state, _keypairs) = TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(
        validator_count,
        &T::default_spec(),
    )
    .build();

    assert_eq!(state.validators.len(), validator_count);
    assert_eq!(state.balances.len(), validator_count);
    assert!(state.previous_epoch_attestations.is_empty());
    assert!(state.current_epoch_attestations.is_empty());
    assert!(state.eth1_data_votes.is_empty());
    assert!(state.historical_roots.is_empty());

    state
}

fn main() {
    let state = build_state::<MainnetEthSpec>(VALIDATOR_COUNT);

    // This vec is an attempt to ensure the compiler doesn't optimize-out the hashing.
    let mut vec = Vec::with_capacity(TREE_HASH_LOOPS);

    for _ in 0..TREE_HASH_LOOPS {
        let root = state.canonical_root();
        vec.push(root[0]);
    }
}
