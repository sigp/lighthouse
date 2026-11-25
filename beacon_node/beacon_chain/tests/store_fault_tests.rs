#![cfg(not(debug_assertions))]

//! Tests for the handling of database write failures during block and payload envelope import.
//!
//! If the node fails to write a block to disk after its been imported to fork choice, this puts
//! fork choice in an inconsistent state. We call this missing block a "phantom" block.
//! A node that continues running in this state is stuck
//!
//! - the node refuses to re-import the phantom block.
//! - children of the phantom block fail with `MissingBeaconBlock` instead of `ParentUnknown`,
//! - head recomputation fails and the head cannot advance.
//!
//! The same applies to a payload envelope that fork choice has marked as received but that is
//! missing from disk, i.e. a "phantom" payload.
//!
//! On a failed write we mark fork choice as poisoned and initiate a forced shutdown. The poisoned
//! fork choice is never persisted to disk, so a restart recovers the last valid fork choice from
//! disk.

use beacon_chain::{
    BeaconChainError, BlockError, NotifyExecutionLayer,
    payload_envelope_verification::{EnvelopeError, EnvelopeSource},
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
        fork_name_from_env,
    },
};
use eth2::types::SignedBlockContentsTuple;
use proto_array::PayloadStatus;
use std::sync::Arc;
use task_executor::ShutdownReason;
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = Spec;

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

/// Build a harness with a two epoch long chain.
async fn harness_with_chain() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(Spec::default())
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

    harness
}

/// Build a chain, then import a block while every store operation fails.
///
/// The import adds the block to fork choice, then fails the database write. The returned
/// chain has a fork choice containing `phantom_root` while the store does not.
async fn wedged_chain() -> WedgedChain {
    let harness = harness_with_chain().await;

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

    // The failure poisons fork choice and requests shutdown.
    assert!(
        harness.chain.canonical_head.fork_choice_poisoned(),
        "fork choice should be poisoned"
    );
    assert_eq!(
        harness.shutdown_reasons(),
        vec![ShutdownReason::Failure(
            "Database write failure during block or payload envelope import"
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

    // Head recomputation is a no-op while fork choice is poisoned, so the head never
    // advances to the phantom block.
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

    // A graceful shutdown refuses to persist the poisoned fork choice.
    let err = harness.chain.persist_fork_choice().unwrap_err();
    assert!(
        matches!(err, BeaconChainError::ForkChoicePoisoned),
        "persisting should refuse due to the poisoned fork choice, got: {err:?}"
    );
    drop(harness);

    // Rebooting from the same database succeeds, resolving the head from the last
    // consistent fork choice on disk.
    let harness = BeaconChainHarness::builder(Spec::default())
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

/// The payload envelope counterpart of `db_write_failure_poisons_fork_choice_and_shuts_down`.
///
/// The envelope import marks the payload as received in fork choice, then fails the database
/// write. This leaves a "phantom" payload: fork choice has a `Full` node for the block while the
/// store has no envelope for it.
#[tokio::test]
async fn payload_db_write_failure_poisons_fork_choice_and_shuts_down() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let harness = harness_with_chain().await;

    // Import a block, withholding its payload envelope.
    let state = harness.get_current_state();
    let slot = harness.chain.slot().unwrap() + 1;
    let (block_contents, envelope, _) = harness.make_block_with_envelope(state, slot).await;
    let block = block_contents.0.clone();
    let block_root = block.canonical_root();
    harness
        .process_block(slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    // Without its custody columns the envelope never reaches fork choice.
    harness.process_gossip_columns(&block, None).await;

    let envelope = Arc::new(envelope.expect("Gloas block should produce an envelope"));
    let verified_envelope = harness
        .chain
        .verify_envelope_for_gossip(envelope, EnvelopeSource::Gossip)
        .await
        .expect("envelope should pass gossip verification");

    // Fail the envelope's database write and every store operation after it.
    harness
        .chain
        .store
        .hot_db
        .inject_faults_on_next_payload_envelope_write();

    let err = harness
        .chain
        .process_execution_payload_envelope(
            block_root,
            verified_envelope,
            NotifyExecutionLayer::Yes,
            BlockImportSource::Gossip,
            || Ok(()),
        )
        .await
        .unwrap_err();
    match err {
        BlockError::EnvelopeError(e) => assert!(
            matches!(*e, EnvelopeError::BeaconChainError(_)),
            "import should fail with an internal error, got: {e:?}"
        ),
        other => panic!("expected an internal envelope error, got: {other:?}"),
    }

    // The resource exhaustion passes, but the damage is done.
    harness.chain.store.hot_db.inject_faults(false);

    // fork choice has received the phantom payload, the store has not.
    assert!(
        harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .is_payload_received(&block_root),
        "fork choice should have received the phantom payload"
    );
    assert!(
        harness
            .chain
            .get_payload_envelope(&block_root)
            .unwrap()
            .is_none(),
        "the store should not contain the phantom payload"
    );

    // The failure poisons fork choice and requests shutdown.
    assert!(
        harness.chain.canonical_head.fork_choice_poisoned(),
        "fork choice should be poisoned"
    );
    assert_eq!(
        harness.shutdown_reasons(),
        vec![ShutdownReason::Failure(
            "Database write failure during block or payload envelope import"
        )],
        "the chain should request shutdown"
    );

    // Head recomputation is a no-op while fork choice is poisoned, so the head never advances
    // to the phantom payload.
    harness.chain.recompute_head_at_current_slot().await;
    let head = harness.chain.canonical_head.cached_head();
    assert_eq!(
        head.head_block_root(),
        block_root,
        "the block itself imported fine and should be the head"
    );
    assert_ne!(
        head.head_payload_status(),
        PayloadStatus::Full,
        "the head should not advance to the phantom payload"
    );
}
