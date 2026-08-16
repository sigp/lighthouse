#![cfg(not(debug_assertions))]

//! Tests for the handling of database write failures during block import.
//!
//! If the node fails to write a block to disk after its been imported to fork choice, this puts
//! fork choice in an inconsistent state. We call this missing block a "phantom" block.
//! A node that continues running in this state is stuck
//!
//! - the node refuses to re-import the phantom block.
//! - children of the phantom block fail with `MissingBeaconBlock` instead of `ParentUnknown`,
//! - head recomputation fails and the head cannot advance.
//!
//! The node first tries to restore the last persisted fork choice from disk. If the restore fails
//! we mark fork choice as poisoned and initiate a forced shutdown. The posioned fork choice is
//! never persisted to disk, so a restart recovers the last valid fork choice from disk and re-syncs
//! any missing blocks, including the phantom block.

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
/// The import adds the block to fork choice, then fails the database write, then fails
/// the restore of fork choice from the store. The returned chain has a fork choice
/// containing `phantom_root` while the store does not.
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

    // The restore from the store fails too, so the failure poisons fork choice and requests
    // shutdown.
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

    // The assertions below pin the "stuck node" behaviour that makes shutdown the only safe
    // option. Until the process exits the node refuses to re-import the phantom block, because
    // duplicate detection only checks fork choice.
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

/// A transient write failure is recoverabe by restoring fork choice from the store.
/// No shutdown is requested.
#[tokio::test]
async fn transient_db_write_failure_restores_fork_choice() {
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

    let head_root_before = harness.chain.canonical_head.cached_head().head_block_root();
    let state = harness.get_current_state();
    let slot = harness.chain.slot().unwrap() + 1;
    let (block_contents, _) = harness.make_block(state, slot).await;
    let block_root = block_contents.0.canonical_root();

    // Fail only the block's database write. Reads and later writes succeed.
    harness
        .chain
        .store
        .hot_db
        .inject_transient_fault_on_next_block_write();

    let err = harness
        .process_block(slot, block_root, block_contents.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, BlockError::BeaconChainError(_)),
        "import should fail with an internal error, got: {err:?}"
    );

    // Fork choice was restored from the store, so it no longer contains the block and is
    // consistent with the store again.
    assert!(
        !harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .contains_block(&block_root),
        "fork choice should not contain the block after the restore"
    );
    assert!(
        !harness.chain.canonical_head.fork_choice_poisoned(),
        "fork choice should not be poisoned"
    );
    assert!(
        harness.shutdown_reasons().is_empty(),
        "the chain should not request shutdown"
    );
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_block_root(),
        head_root_before,
        "the head should be unchanged"
    );

    // The block can be re-imported and becomes the head.
    harness
        .process_block(slot, block_root, block_contents)
        .await
        .unwrap();
    harness.chain.recompute_head_at_current_slot().await;
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_block_root(),
        block_root,
        "the head should advance to the re-imported block"
    );
    harness.chain.persist_fork_choice().unwrap();
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

    // A graceful shutdown refuses to persist the poisoned fork choice.
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

/// Persisting fork choice checks the store for every block, so it refuses even when the
/// poison flag was never set.
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
