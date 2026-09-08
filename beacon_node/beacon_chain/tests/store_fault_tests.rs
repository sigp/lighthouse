#![cfg(not(debug_assertions))]

//! Tests for divergence between fork choice and the store when the db fails
//! during block import.
//!
//! If the database write for a block fails after the block has been added to
//! fork choice, and the recovery step `handle_import_block_db_write_error` also fails,
//! then fork choice contains a block that the store does not. These tests check for the
//! following behaviour:
//!
//! - The node refuses to re-import the missing block.
//! - Children of the missing block fail with `MissingBeaconBlock` instead of `ParentUnknown`.
//! - Head recomputation fails and the head cannot advance.
//! - A graceful shutdown persists the diverged fork choice, making the next startup fail
//!   with "Head block not found in store".

use beacon_chain::{
    BeaconChainError, BlockError,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
        fork_name_from_env,
    },
};
use eth2::types::SignedBlockContentsTuple;
use std::panic::{AssertUnwindSafe, catch_unwind};
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = MinimalEthSpec;

fn incompatible_fork() -> bool {
    fork_name_from_env().is_some_and(|f| !f.bellatrix_enabled() || f.gloas_enabled())
}

struct WedgedChain {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    /// Root of the block that is in fork choice but not in the store, i.e. the phantom block.
    phantom_root: Hash256,
    phantom_slot: Slot,
    phantom_contents: SignedBlockContentsTuple<E>,
    /// Post-state of the phantom block, for building a child block.
    post_state: BeaconState<E>,
}

/// Build a chain, then import a block while every store operation fails.
///
/// The import adds the block to fork choice, then fails the database write, then fails
/// the recovery read. The returned chain has a fork choice containing `phantom_root`
/// while the store does not.
async fn wedged_chain() -> WedgedChain {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();
    harness
        .extend_chain(
            2 * E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let state = harness.get_current_state();
    let slot = harness.chain.slot().unwrap() + 1;
    let (phantom_contents, post_state) = harness.make_block(state, slot).await;
    let phantom_root = phantom_contents.0.canonical_root();

    // Fail the block's database write and every store operation after it.
    harness
        .chain
        .store
        .hot_db
        .inject_faults_on_next_block_write();

    let err = harness
        .process_block(slot, phantom_root, phantom_contents.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, BlockError::BeaconChainError(_)),
        "import should fail with an internal error, got: {err:?}"
    );

    // The resource exhaustion passes, but the damage is done.
    harness.chain.store.hot_db.inject_faults(false);

    WedgedChain {
        harness,
        phantom_root,
        phantom_slot: slot,
        phantom_contents,
        post_state,
    }
}

// TODO: this test asserts the *broken* behaviour. Once the divergence is fixed (e.g. by
// reverting fork choice in memory or refusing to run diverged), this test should FAIL.
// Flip the assertions to the healed behaviour as part of the fix.
#[tokio::test]
async fn db_write_failure_diverges_fork_choice_from_store() {
    if incompatible_fork() {
        return;
    }
    let WedgedChain {
        harness,
        phantom_root,
        phantom_slot,
        phantom_contents,
        post_state,
    } = wedged_chain().await;

    // fork choice contains the phantom block, the store does not.
    assert!(
        harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .contains_block(&phantom_root),
        "fork choice should contain the phantom block"
    );
    assert!(
        harness
            .chain
            .get_blinded_block(&phantom_root)
            .unwrap()
            .is_none(),
        "the store should not contain the phantom block"
    );

    // The node refuses to re-import the phantom block, because duplicate detection only
    // checks fork choice.
    let err = harness
        .process_block(phantom_slot, phantom_root, phantom_contents)
        .await
        .unwrap_err();
    assert!(
        matches!(err, BlockError::DuplicateFullyImported(root) if root == phantom_root),
        "re-import should be treated as a duplicate, got: {err:?}"
    );

    // A child of the phantom block fails with `MissingBeaconBlock` rather than
    // `ParentUnknown`, because the parent lookup checks fork choice before the store.
    let child_slot = phantom_slot + 1;
    let (child_contents, _) = harness.make_block(post_state, child_slot).await;
    let child_root = child_contents.0.canonical_root();
    let err = harness
        .process_block(child_slot, child_root, child_contents)
        .await
        .unwrap_err();
    match err {
        BlockError::BeaconChainError(e) => assert!(
            matches!(*e, BeaconChainError::MissingBeaconBlock(root) if root == phantom_root),
            "child import should fail on the missing parent, got: {e:?}"
        ),
        other => panic!("expected MissingBeaconBlock for the child block, got: {other:?}"),
    }

    // Head recomputation cannot load the fork choice head from the store, so the head
    // never advances to the phantom block.
    harness.chain.recompute_head_at_current_slot().await;
    assert_ne!(
        harness.chain.canonical_head.cached_head().head_block_root(),
        phantom_root,
        "the head should not advance to the phantom block"
    );
}

// TODO: this test asserts the *broken* behaviour. Once shutdown stops persisting a
// known-diverged fork choice (or startup self-heals), this test should FAIL. Flip the
// assertions to the healed behaviour as part of the fix.
#[tokio::test]
async fn restart_after_db_write_failure_is_fatal() {
    if incompatible_fork() {
        return;
    }
    let WedgedChain { harness, .. } = wedged_chain().await;

    let store = harness.chain.store.clone();
    let slot_clock = harness.chain.slot_clock.clone();

    // A graceful shutdown persists the diverged fork choice (see `Drop` for
    // `BeaconChain`).
    harness.chain.persist_fork_choice().unwrap();
    drop(harness);

    // Rebooting from the same database fails, because the persisted fork choice resolves
    // a head block that was never written to the store.
    let result = catch_unwind(AssertUnwindSafe(|| {
        BeaconChainHarness::builder(MinimalEthSpec)
            .default_spec()
            .deterministic_keypairs(VALIDATOR_COUNT)
            .resumed_ephemeral_store(store)
            .mock_execution_layer()
            .testing_slot_clock(slot_clock)
            .build()
    }));

    let panic_payload = result.expect_err("the beacon chain should fail to start");
    let message = panic_payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic_payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(
        message.contains("Head block not found in store"),
        "startup should fail on the missing head block, got: {message}"
    );
}
