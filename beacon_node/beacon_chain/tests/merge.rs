use beacon_chain::test_utils::BeaconChainHarness;
use std::str::FromStr;
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

    /*
     * Start with the base fork.
     */

    assert!(harness.chain.head().unwrap().beacon_block.as_base().is_ok());

    /*
     * Do the Altair fork.
     */

    harness.extend_to_slot(altair_fork_slot);

    let altair_head = harness.chain.head().unwrap().beacon_block;
    assert!(altair_head.as_altair().is_ok());
    assert_eq!(altair_head.slot(), altair_fork_slot);

    /*
     * Do the merge fork, without a terminal PoW block.
     */

    harness.extend_to_slot(merge_fork_slot);

    let merge_head = harness.chain.head().unwrap().beacon_block;
    assert!(merge_head.as_merge().is_ok());
    assert_eq!(merge_head.slot(), merge_fork_slot);
    assert_eq!(
        *merge_head.message().body().execution_payload().unwrap(),
        ExecutionPayload::default()
    );

    /*
     * Next merge block shouldn't include an exec payload.
     */

    harness.extend_slots(1);

    let one_after_merge_head = harness.chain.head().unwrap().beacon_block;
    assert_eq!(
        *one_after_merge_head
            .message()
            .body()
            .execution_payload()
            .unwrap(),
        ExecutionPayload::default()
    );
    assert_eq!(one_after_merge_head.slot(), merge_fork_slot + 1);

    /*
     * Trigger the terminal PoW block.
     */

    harness
        .execution_block_generator()
        .move_to_terminal_block()
        .unwrap();

    /*
     * Next merge block should include an exec payload.
     */

    harness.extend_slots(1);

    let first_post_ttd_block = harness.chain.head().unwrap().beacon_block;
    assert!(
        *first_post_ttd_block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            != ExecutionPayload::default()
    );
}

#[test]
fn geth_merge() {
    let altair_fork_epoch = Epoch::new(4);
    let altair_fork_slot = altair_fork_epoch.start_slot(E::slots_per_epoch());
    let merge_fork_epoch = Epoch::new(8);
    let merge_fork_slot = merge_fork_epoch.start_slot(E::slots_per_epoch());

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.merge_fork_epoch = Some(merge_fork_epoch);
    spec.terminal_total_difficulty = Uint256::from(0x400000000_u64);
    spec.terminal_block_hash =
        Hash256::from_str("0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174")
            .unwrap();

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .execution_layer(&["http://127.0.0.1:8545"])
        .build();

    /*
     * Start with the base fork.
     */

    assert!(harness.chain.head().unwrap().beacon_block.as_base().is_ok());

    /*
     * Do the Altair fork.
     */

    harness.extend_to_slot(altair_fork_slot);

    let altair_head = harness.chain.head().unwrap().beacon_block;
    assert!(altair_head.as_altair().is_ok());
    assert_eq!(altair_head.slot(), altair_fork_slot);

    /*
     * Do the merge fork, without a terminal PoW block.
     */

    harness.extend_to_slot(merge_fork_slot);

    let merge_head = harness.chain.head().unwrap().beacon_block;
    assert!(merge_head.as_merge().is_ok());
    assert_eq!(merge_head.slot(), merge_fork_slot);
    assert_eq!(
        *merge_head.message().body().execution_payload().unwrap(),
        ExecutionPayload::default()
    );

    /*
     * Next merge block shouldn't include an exec payload.
     */

    harness.extend_slots(1);

    let one_after_merge_head = harness.chain.head().unwrap().beacon_block;
    assert_eq!(
        *one_after_merge_head
            .message()
            .body()
            .execution_payload()
            .unwrap(),
        ExecutionPayload::default()
    );
    assert_eq!(one_after_merge_head.slot(), merge_fork_slot + 1);

    /*
     * Next merge block should include an exec payload.
     */

    harness.extend_slots(1);

    let first_post_ttd_block = harness.chain.head().unwrap().beacon_block;
    assert!(
        *first_post_ttd_block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            != ExecutionPayload::default()
    );
}
