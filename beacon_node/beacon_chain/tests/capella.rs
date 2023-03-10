#![cfg(not(debug_assertions))] // Tests run too slow in debug.

use beacon_chain::test_utils::BeaconChainHarness;
use execution_layer::test_utils::Block;
use types::*;

const VALIDATOR_COUNT: usize = 32;
type E = MainnetEthSpec;

fn verify_execution_payload_chain<T: EthSpec>(chain: &[FullPayload<T>]) {
    let mut prev_ep: Option<FullPayload<T>> = None;

    for ep in chain {
        assert!(!ep.is_default_with_empty_roots());
        assert!(ep.block_hash() != ExecutionBlockHash::zero());

        // Check against previous `ExecutionPayload`.
        if let Some(prev_ep) = prev_ep {
            assert_eq!(prev_ep.block_hash(), ep.parent_hash());
            assert_eq!(prev_ep.block_number() + 1, ep.block_number());
            assert!(ep.timestamp() > prev_ep.timestamp());
        }
        prev_ep = Some(ep.clone());
    }
}

#[tokio::test]
async fn base_altair_merge_capella() {
    let altair_fork_epoch = Epoch::new(4);
    let altair_fork_slot = altair_fork_epoch.start_slot(E::slots_per_epoch());
    let bellatrix_fork_epoch = Epoch::new(8);
    let merge_fork_slot = bellatrix_fork_epoch.start_slot(E::slots_per_epoch());
    let capella_fork_epoch = Epoch::new(12);
    let capella_fork_slot = capella_fork_epoch.start_slot(E::slots_per_epoch());

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
    spec.capella_fork_epoch = Some(capella_fork_epoch);

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec)
        .logger(logging::test_logger())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    /*
     * Start with the base fork.
     */
    assert!(harness.chain.head_snapshot().beacon_block.as_base().is_ok());

    /*
     * Do the Altair fork.
     */
    harness.extend_to_slot(altair_fork_slot).await;

    let altair_head = &harness.chain.head_snapshot().beacon_block;
    assert!(altair_head.as_altair().is_ok());
    assert_eq!(altair_head.slot(), altair_fork_slot);

    /*
     * Do the merge fork, without a terminal PoW block.
     */
    harness.extend_to_slot(merge_fork_slot).await;

    let merge_head = &harness.chain.head_snapshot().beacon_block;
    assert!(merge_head.as_merge().is_ok());
    assert_eq!(merge_head.slot(), merge_fork_slot);
    assert!(
        merge_head
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .is_default_with_empty_roots(),
        "Merge head is default payload"
    );

    /*
     * Next merge block shouldn't include an exec payload.
     */
    harness.extend_slots(1).await;

    let one_after_merge_head = &harness.chain.head_snapshot().beacon_block;
    assert!(
        one_after_merge_head
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .is_default_with_empty_roots(),
        "One after merge head is default payload"
    );
    assert_eq!(one_after_merge_head.slot(), merge_fork_slot + 1);

    /*
     * Trigger the terminal PoW block.
     */
    harness
        .execution_block_generator()
        .move_to_terminal_block()
        .unwrap();

    // Add a slot duration to get to the next slot
    let timestamp = harness.get_timestamp_at_slot() + harness.spec.seconds_per_slot;
    harness
        .execution_block_generator()
        .modify_last_block(|block| {
            if let Block::PoW(terminal_block) = block {
                terminal_block.timestamp = timestamp;
            }
        });
    harness.extend_slots(1).await;

    let two_after_merge_head = &harness.chain.head_snapshot().beacon_block;
    assert!(
        two_after_merge_head
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .is_default_with_empty_roots(),
        "Two after merge head is default payload"
    );
    assert_eq!(two_after_merge_head.slot(), merge_fork_slot + 2);

    /*
     * Next merge block should include an exec payload.
     */
    let mut execution_payloads = vec![];
    for _ in (merge_fork_slot.as_u64() + 3)..capella_fork_slot.as_u64() {
        harness.extend_slots(1).await;
        let block = &harness.chain.head_snapshot().beacon_block;
        let full_payload: FullPayload<E> = block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .clone()
            .into();
        // pre-capella shouldn't have withdrawals
        assert!(full_payload.withdrawals_root().is_err());
        execution_payloads.push(full_payload);
    }

    /*
     * Should enter capella fork now.
     */
    for _ in 0..16 {
        harness.extend_slots(1).await;
        let block = &harness.chain.head_snapshot().beacon_block;
        let full_payload: FullPayload<E> = block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .clone()
            .into();
        // post-capella should have withdrawals
        assert!(full_payload.withdrawals_root().is_ok());
        execution_payloads.push(full_payload);
    }

    verify_execution_payload_chain(execution_payloads.as_slice());
}
