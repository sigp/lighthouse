#![cfg(not(debug_assertions))]

//! Restart resilience for the Fast Confirmation Rule: a restarted node keeps announcing the root it
//! confirmed before the restart until the re-seeded rule catches up, unless that root is old enough
//! that it should already have been finalized.

use beacon_chain::{
    BeaconChain,
    chain_config::{ChainConfig, FastConfirmationMode},
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, test_spec,
    },
};
use slot_clock::SlotClock;
use types::{EthSpec, Hash256, MinimalEthSpec, Slot};

type E = MinimalEthSpec;
type Harness = BeaconChainHarness<EphemeralHarnessType<E>>;

const VALIDATOR_COUNT: usize = 64;

/// Enough epochs for the chain to finalize and for FCR to confirm a block well ahead of the
/// finalized checkpoint.
const EPOCHS_BEFORE_RESTART: u64 = 5;

/// A chain that has confirmed a recent block and then been shut down gracefully. The harness is
/// kept alive because the restarted chain reuses its store and its mock execution layer.
struct PreRestart {
    harness: Harness,
    confirmed_root: Hash256,
    confirmed_slot: Slot,
}

fn chain_config() -> ChainConfig {
    ChainConfig {
        fast_confirmation: FastConfirmationMode::Enabled,
        ..ChainConfig::default()
    }
}

fn confirmed_roots(chain: &BeaconChain<EphemeralHarnessType<E>>) -> (Hash256, Hash256) {
    let fcr = chain
        .canonical_head
        .fast_confirmation
        .as_ref()
        .expect("FCR is enabled")
        .lock();
    (fcr.confirmed_root, fcr.restart_resilient_confirmed_root)
}

fn slot_of(chain: &BeaconChain<EphemeralHarnessType<E>>, root: Hash256) -> Slot {
    chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&root)
        .expect("block is in fork choice")
        .slot
}

/// Build a chain that has finalized and confirmed a recent block, then persist it as a graceful
/// shutdown would.
async fn confirm_then_shut_down() -> PreRestart {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(test_spec::<E>().into())
        .chain_config(chain_config())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .mock_execution_layer()
        .fresh_ephemeral_store()
        .build();

    harness.advance_slot();
    harness
        .extend_chain(
            (EPOCHS_BEFORE_RESTART * E::slots_per_epoch()) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (confirmed_root, announced_root) = confirmed_roots(&harness.chain);
    assert_eq!(
        confirmed_root, announced_root,
        "with nothing persisted before this run, FCR announces its own confirmed root"
    );
    assert_ne!(
        announced_root,
        harness.finalized_checkpoint().root,
        "FCR should have confirmed a block ahead of the finalized checkpoint"
    );

    harness
        .chain
        .persist_fork_choice()
        .expect("should persist fork choice");

    PreRestart {
        confirmed_root: announced_root,
        confirmed_slot: slot_of(&harness.chain, announced_root),
        harness,
    }
}

/// Restart the chain `previous` was running, after `slots_of_downtime` slots have gone by on the
/// wall clock. The store, the slot clock and the execution layer are the ones it was using.
fn restart(previous: &Harness, slots_of_downtime: u64) -> Harness {
    let slot_clock = previous.chain.slot_clock.clone();
    let restart_slot = slot_clock.now().expect("should have a slot") + slots_of_downtime;
    slot_clock.set_slot(restart_slot.as_u64());

    BeaconChainHarness::builder(MinimalEthSpec)
        .spec(test_spec::<E>().into())
        .chain_config(chain_config())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .execution_layer(previous.chain.execution_layer.clone())
        .resumed_ephemeral_store(previous.chain.store.clone())
        .testing_slot_clock(slot_clock)
        .build()
}

#[tokio::test]
async fn announces_the_root_confirmed_before_the_restart() {
    let pre = confirm_then_shut_down().await;

    let harness = restart(&pre.harness, 1);
    harness.chain.recompute_head_at_current_slot().await;

    let (confirmed_root, announced_root) = confirmed_roots(&harness.chain);
    assert_eq!(
        confirmed_root,
        harness.finalized_checkpoint().root,
        "a freshly seeded FCR has not re-confirmed anything yet"
    );
    assert_eq!(
        announced_root, pre.confirmed_root,
        "the root confirmed before the restart should still be announced"
    );

    // The EL is told about the same block, so its safe block hash does not regress either.
    let safe_block_hash = harness
        .chain
        .canonical_head
        .cached_head()
        .forkchoice_update_parameters()
        .justified_hash;
    let expected_hash = harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&pre.confirmed_root)
        .expect("block is in fork choice")
        .checkpoint_payload_block_hash();
    assert_eq!(safe_block_hash, expected_hash);

    // Once FCR confirms a block of its own the pre-restart root is left behind.
    harness
        .extend_chain(
            (2 * E::slots_per_epoch()) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (confirmed_root, announced_root) = confirmed_roots(&harness.chain);
    assert_eq!(
        confirmed_root, announced_root,
        "FCR has caught up, so it announces its own confirmed root again"
    );
    assert!(
        slot_of(&harness.chain, announced_root) > pre.confirmed_slot,
        "the confirmed root should have advanced past the pre-restart root"
    );
}

#[tokio::test]
async fn does_not_announce_a_root_that_was_reorged_out() {
    let pre = confirm_then_shut_down().await;

    let harness = restart(&pre.harness, 1);
    let first_slot = harness.chain.slot().expect("should have a slot");
    // Build a fork from the parent of the pre-restart root and let every validator attest to it, so
    // the head leaves that branch.
    harness
        .extend_chain(
            2,
            BlockStrategy::ForkCanonicalChainAt {
                previous_slot: pre.confirmed_slot - 1,
                first_slot,
            },
            AttestationStrategy::AllValidators,
        )
        .await;

    assert!(
        !harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .is_descendant(pre.confirmed_root, harness.head_block_root()),
        "the fork should have reorged the pre-restart root out"
    );
    assert!(
        pre.confirmed_slot.epoch(E::slots_per_epoch()) + 2
            > harness.chain.epoch().expect("should have an epoch"),
        "the pre-restart root must still be recent, or it would be dropped as stale instead"
    );

    let (confirmed_root, announced_root) = confirmed_roots(&harness.chain);
    assert_eq!(
        confirmed_root, announced_root,
        "a root off the head's chain cannot be announced: the EL rejects such a safe block hash"
    );
}

#[tokio::test]
async fn falls_back_to_finalized_after_a_long_downtime() {
    let pre = confirm_then_shut_down().await;

    // Three epochs of downtime is long enough that the pre-restart root should have been finalized
    // by now: if it wasn't, finality is delayed and the root cannot be trusted.
    let harness = restart(&pre.harness, 3 * E::slots_per_epoch());
    harness.chain.recompute_head_at_current_slot().await;

    let (_, announced_root) = confirmed_roots(&harness.chain);
    assert_ne!(
        announced_root, pre.confirmed_root,
        "a stale pre-restart root must not be announced"
    );
    assert_eq!(
        announced_root,
        harness.finalized_checkpoint().root,
        "FCR should fall back to the finalized block"
    );
}
