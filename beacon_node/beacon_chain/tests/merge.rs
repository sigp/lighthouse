#![cfg(not(debug_assertions))] // Tests run too slow in debug.

use beacon_chain::test_utils::BeaconChainHarness;
use execution_layer::test_utils::{generate_pow_block, Block, DEFAULT_TERMINAL_BLOCK};
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
            assert_eq!(prev_ep.block_hash(), ep.execution_payload().parent_hash());
            assert_eq!(
                prev_ep.execution_payload().block_number() + 1,
                ep.execution_payload().block_number()
            );
            assert!(ep.execution_payload().timestamp() > prev_ep.execution_payload().timestamp());
        }
        prev_ep = Some(ep.clone());
    }
}

#[tokio::test]
// TODO(merge): This isn't working cause the non-zero values in `initialize_beacon_state_from_eth1`
// are causing failed lookups to the execution node. I need to come back to this.
#[should_panic]
async fn merge_with_terminal_block_hash_override() {
    let altair_fork_epoch = Epoch::new(0);
    let bellatrix_fork_epoch = Epoch::new(0);

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);

    let genesis_pow_block_hash = generate_pow_block(
        spec.terminal_total_difficulty,
        DEFAULT_TERMINAL_BLOCK,
        0,
        ExecutionBlockHash::zero(),
    )
    .unwrap()
    .block_hash;

    spec.terminal_block_hash = genesis_pow_block_hash;

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec)
        .logger(logging::test_logger())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    assert_eq!(
        harness
            .execution_block_generator()
            .latest_block()
            .unwrap()
            .block_hash(),
        genesis_pow_block_hash,
        "pre-condition"
    );

    assert!(
        harness
            .chain
            .head_snapshot()
            .beacon_block
            .as_merge()
            .is_ok(),
        "genesis block should be a merge block"
    );

    let mut execution_payloads = vec![];
    for i in 0..E::slots_per_epoch() * 3 {
        harness.extend_slots(1).await;

        let block = &harness.chain.head_snapshot().beacon_block;

        let execution_payload = block.message().body().execution_payload().unwrap().clone();
        if i == 0 {
            assert_eq!(execution_payload.block_hash(), genesis_pow_block_hash);
        }
        execution_payloads.push(execution_payload.into());
    }

    verify_execution_payload_chain(execution_payloads.as_slice());
}

#[tokio::test]
async fn base_altair_merge_with_terminal_block_after_fork() {
    let altair_fork_epoch = Epoch::new(4);
    let altair_fork_slot = altair_fork_epoch.start_slot(E::slots_per_epoch());
    let bellatrix_fork_epoch = Epoch::new(8);
    let merge_fork_slot = bellatrix_fork_epoch.start_slot(E::slots_per_epoch());

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);

    let mut execution_payloads = vec![];

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

    let one_after_merge_head = &harness.chain.head_snapshot().beacon_block;
    // FIXME: why is this being tested twice?
    assert!(
        one_after_merge_head
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .is_default_with_empty_roots(),
        "One after merge head is default payload"
    );
    assert_eq!(one_after_merge_head.slot(), merge_fork_slot + 2);

    /*
     * Next merge block should include an exec payload.
     */
    for _ in 0..4 {
        harness.extend_slots(1).await;

        let block = &harness.chain.head_snapshot().beacon_block;
        execution_payloads.push(
            block
                .message()
                .body()
                .execution_payload()
                .unwrap()
                .clone()
                .into(),
        );
    }

    verify_execution_payload_chain(execution_payloads.as_slice());
}
