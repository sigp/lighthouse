use beacon_chain::test_utils::BeaconChainHarness;
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = MainnetEthSpec;

#[test]
fn basic_merge() {
    let altair_fork_epoch = Epoch::new(4);
    let altair_fork_slot = altair_fork_epoch.start_slot(E::slots_per_epoch());
    let merge_fork_epoch = Epoch::new(8);
    let merge_fork_slot = merge_fork_epoch.start_slot(E::slots_per_epoch());

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.merge_fork_epoch = Some(merge_fork_epoch);

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    assert!(harness.chain.head().unwrap().beacon_block.as_base().is_ok());

    harness.extend_to_slot(altair_fork_slot);

    assert!(harness
        .chain
        .head()
        .unwrap()
        .beacon_block
        .as_altair()
        .is_ok());

    harness.extend_to_slot(merge_fork_slot);

    let head_block = harness.chain.head().unwrap().beacon_block;
    assert!(head_block.as_merge().is_ok());
    assert_eq!(
        *head_block.message().body().execution_payload().unwrap(),
        ExecutionPayload::default()
    );

    harness.extend_slots(1);

    assert_eq!(
        *head_block.message().body().execution_payload().unwrap(),
        ExecutionPayload::default()
    );

    harness
        .execution_block_generator()
        .move_to_terminal_block()
        .unwrap();

    dbg!(
        harness
            .execution_block_generator()
            .terminal_total_difficulty
    );
    dbg!(spec.terminal_total_difficulty);

    harness.extend_slots(1);

    assert!(
        *head_block.message().body().execution_payload().unwrap() != ExecutionPayload::default()
    );
}
