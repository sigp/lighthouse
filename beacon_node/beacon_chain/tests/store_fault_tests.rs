#![cfg(not(debug_assertions))]

//! Tests for the handling of database write failures during block import.
//!
//! If the database write for a block fails after the block has been added to the in-memory
//! fork choice, then fork choice contains a block that the store does not. There is no
//! reliable in-process recovery: restoring fork choice by reading the database is likely to
//! fail for the same reason the write failed (e.g. file descriptor exhaustion affects both
//! reads and writes), and a node that keeps running with the divergence is wedged:
//!
//! - the node refuses to re-import the phantom block (duplicate detection uses fork choice),
//! - children of the phantom block fail with `MissingBeaconBlock` instead of `ParentUnknown`,
//! - head recomputation fails and the head cannot advance.
//!
//! Instead of running wedged, the chain poisons fork choice and initiates shutdown. The
//! poisoned fork choice is never persisted, so a restart recovers the last consistent fork
//! choice from disk and re-syncs the phantom blocks.

use beacon_chain::{
    BeaconChainError, BlockError,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
        fork_name_from_env,
    },
};
use eth2::types::SignedBlockContentsTuple;
use store::StoreOp;
use task_executor::ShutdownReason;
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
/// The import adds the block to fork choice, then fails the database write. The returned
/// chain has a fork choice containing `phantom_root` while the store does not.
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

#[tokio::test]
async fn db_write_failure_poisons_fork_choice_and_shuts_down() {
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

    // The failure poisons fork choice and requests shutdown, because there is no reliable
    // in-process recovery from the divergence.
    assert!(
        harness.chain.canonical_head.fork_choice_poisoned(),
        "fork choice should be poisoned"
    );
    assert_eq!(
        harness.shutdown_reasons(),
        vec![ShutdownReason::Failure(
            "Database write failure during block import"
        )],
        "the chain should request shutdown"
    );

    // The assertions below pin the wedged behaviour that makes shutdown the only safe
    // option. Until the process exits, the divergence is self-perpetuating:

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

#[tokio::test]
async fn restart_after_db_write_failure_recovers() {
    if incompatible_fork() {
        return;
    }
    let WedgedChain {
        harness,
        phantom_root,
        ..
    } = wedged_chain().await;

    let store = harness.chain.store.clone();
    let slot_clock = harness.chain.slot_clock.clone();

    // A graceful shutdown refuses to persist the poisoned fork choice, keeping the last
    // consistent fork choice on disk (see `Drop` for `BeaconChain`). This check requires no
    // database reads, so it holds even if the database fault is still ongoing.
    let err = harness.chain.persist_fork_choice().unwrap_err();
    assert!(
        matches!(err, BeaconChainError::ForkChoicePoisoned),
        "persisting should refuse due to the poisoned fork choice, got: {err:?}"
    );
    drop(harness);

    // Rebooting from the same database succeeds, resolving the head from the last
    // consistent fork choice on disk.
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .resumed_ephemeral_store(store)
        .mock_execution_layer()
        .testing_slot_clock(slot_clock)
        .build();

    let head_root = harness.chain.canonical_head.cached_head().head_block_root();
    assert_ne!(
        head_root, phantom_root,
        "the recovered head should not be the phantom block"
    );
    assert!(
        harness
            .chain
            .get_blinded_block(&head_root)
            .unwrap()
            .is_some(),
        "the recovered head must exist in the store"
    );
}

/// The persist-time store scan is a second line of defence: it catches divergence that
/// arose without the poison flag being set, e.g. from a database fault on a path that does
/// not run `handle_import_block_db_write_error`.
#[tokio::test]
async fn persist_refuses_diverged_fork_choice() {
    if incompatible_fork() {
        return;
    }
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

    // Delete the head block from the store, leaving fork choice referencing a block that
    // the store does not have.
    let head_root = harness.chain.canonical_head.cached_head().head_block_root();
    harness
        .chain
        .store
        .do_atomically_with_block_and_blobs_cache(vec![StoreOp::DeleteBlock(head_root)])
        .unwrap();

    assert!(
        !harness.chain.canonical_head.fork_choice_poisoned(),
        "the poison flag should not be set"
    );
    let err = harness.chain.persist_fork_choice().unwrap_err();
    assert!(
        matches!(
            err,
            BeaconChainError::ForkChoiceDivergedFromStore { missing_block_root }
                if missing_block_root == head_root
        ),
        "persisting should refuse with the deleted block root, got: {err:?}"
    );
}
