#![cfg(not(debug_assertions))]

//! This file contains regression tests for a bug in fork choice whereby the unrealized justified
//! and finalized checkpoints of a block were assumed to carry over to its child. This is NOT TRUE
//! in general, as the child block may contain slashings which invalidate the
//! justification/finalization from the parent. The tests in this file reproduce this scenario using
//! both attester slashings and proposer slashings.

use beacon_chain::{
    StateSkipConfig,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, test_spec,
    },
};
use state_processing::per_epoch_processing;
use std::sync::Arc;
use types::{Checkpoint, Epoch, EthSpec, MinimalEthSpec, consts::altair::TIMELY_TARGET_FLAG_INDEX};

type E = MinimalEthSpec;

// Proposer slashings are limited to MaxProposerSlashings (16) per block. With 32 validators,
// dropping below the 2/3 justification threshold requires only ~11 slashes, which fits.
const VALIDATOR_COUNT: usize = 32;

fn ceil_two_thirds(value: u64) -> u64 {
    (2 * value).div_ceil(3)
}

struct SameEpochSlashingChild {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    stored_parent_justified: Checkpoint,
    stored_parent_finalized: Checkpoint,
    stored_child_justified: Checkpoint,
    stored_child_finalized: Checkpoint,
    expected_child_justified: Checkpoint,
    expected_child_finalized: Checkpoint,
    parent_epoch: Epoch,
}

/// Basic test checking that the child has correct unrealized justified/finalized checkpoints in the
/// case where the slashings are attester slashings.
#[tokio::test]
async fn child_unrealized_checkpoints_recomputed_after_same_epoch_slashing() {
    let scenario = same_epoch_attester_slashing_child().await;

    assert_eq!(
        scenario.stored_child_justified, scenario.expected_child_justified,
        "child unrealized justified checkpoint should be recomputed from the child state"
    );
    assert_eq!(
        scenario.stored_child_finalized, scenario.expected_child_finalized,
        "child unrealized finalized checkpoint should be recomputed from the child state"
    );
}

/// Variation on the attester slashing test, checking that the inferior justification of the child
/// results in fork choice correctly reverting to the justified checkpoint once the child block is
/// no longer considered viable.
#[tokio::test]
async fn child_with_stale_voting_source_not_head_at_epoch_plus_two() {
    let scenario = same_epoch_attester_slashing_child().await;
    let slots_per_epoch = E::slots_per_epoch();
    let divergence_slot = scenario
        .parent_epoch
        .saturating_add(2u64)
        .start_slot(slots_per_epoch);

    assert_eq!(
        scenario.stored_child_justified, scenario.expected_child_justified,
        "child unrealized justified checkpoint should be recomputed from the child state"
    );
    assert_eq!(
        scenario.stored_child_finalized, scenario.expected_child_finalized,
        "child unrealized finalized checkpoint should be recomputed from the child state"
    );
    assert!(
        scenario.expected_child_justified.epoch.saturating_add(2u64)
            < divergence_slot.epoch(slots_per_epoch),
        "with the spec-computed checkpoint the child is outside the viability window at epoch N + 2"
    );

    while scenario.harness.get_current_slot() < divergence_slot {
        scenario.harness.advance_slot();
    }

    let mut fork_choice = scenario
        .harness
        .chain
        .canonical_head
        .fork_choice_write_lock();
    let head_result = fork_choice.get_head(divergence_slot, &scenario.harness.chain.spec);

    assert_eq!(
        fork_choice.justified_checkpoint(),
        scenario.stored_parent_justified,
        "the store should realize the parent's unrealized justification at the epoch boundary"
    );
    assert_eq!(
        fork_choice.finalized_checkpoint(),
        scenario.stored_parent_finalized,
        "the store should realize the parent's unrealized finalization at the epoch boundary"
    );

    // No epoch N + 1 blocks were produced after the slashing child. Under the spec-computed child
    // checkpoint, the child is the only leaf below the justified root and is outside the viability
    // window. The spec-correct result is to set the justified checkpoint as the head.
    assert_eq!(
        head_result.unwrap().0,
        fork_choice.justified_checkpoint().root
    );
}

/// Basic test checking child checkpoints but with proposer slashings instead of attester slashings.
#[tokio::test]
async fn child_unrealized_checkpoints_recomputed_after_same_epoch_proposer_slashing() {
    let scenario = same_epoch_proposer_slashing_child().await;

    assert_eq!(
        scenario.stored_child_justified, scenario.expected_child_justified,
        "child unrealized justified checkpoint should be recomputed from the child state"
    );
    assert_eq!(
        scenario.stored_child_finalized, scenario.expected_child_finalized,
        "child unrealized finalized checkpoint should be recomputed from the child state"
    );
}

async fn same_epoch_attester_slashing_child() -> SameEpochSlashingChild {
    same_epoch_slashing_child(VALIDATOR_COUNT, |harness, slash_indices| {
        harness
            .add_attester_slashing(slash_indices.to_vec())
            .expect("should add attester slashing to operation pool");
    })
    .await
}

async fn same_epoch_proposer_slashing_child() -> SameEpochSlashingChild {
    same_epoch_slashing_child(VALIDATOR_COUNT, |harness, slash_indices| {
        for &index in slash_indices {
            harness
                .add_proposer_slashing(index)
                .expect("should add proposer slashing to operation pool");
        }
    })
    .await
}

/// Generic scenario builder with `inject_slashings` capable of injecting attester or proposer
/// slashings.
async fn same_epoch_slashing_child<F>(
    validator_count: usize,
    inject_slashings: F,
) -> SameEpochSlashingChild
where
    F: FnOnce(&BeaconChainHarness<EphemeralHarnessType<E>>, &[u64]),
{
    let spec = test_spec::<E>();

    let harness: BeaconChainHarness<EphemeralHarnessType<E>> =
        BeaconChainHarness::builder(E::default())
            .spec(Arc::new(spec))
            .deterministic_keypairs(validator_count)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

    let slots_per_epoch = E::slots_per_epoch();

    // Minimum warm-up for the parent to reach FFG steady state (justified == epoch, finalized ==
    // epoch - 1); 2 epochs is too few.
    let warmup_epochs: u64 = 3;
    harness.advance_slot();
    harness
        .extend_chain(
            slots_per_epoch as usize * warmup_epochs as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let parent_epoch = Epoch::new(warmup_epochs);
    // ceil(Minimal::slots_per_epoch() * 2/3) = 6
    let parent_slot = parent_epoch.start_slot(slots_per_epoch) + 6;
    let parent_root = harness.extend_to_slot(parent_slot).await;

    let mut parent_state = harness
        .chain
        .state_at_slot(parent_slot, StateSkipConfig::WithStateRoots)
        .expect("should load parent state");
    parent_state
        .build_caches(&harness.chain.spec)
        .expect("should build parent state caches");

    let total_active_balance = parent_state
        .get_total_active_balance()
        .expect("should get parent total active balance");
    let required_balance = ceil_two_thirds(total_active_balance);
    let effective_balance = parent_state
        .validators()
        .get(0)
        .expect("validator 0 should exist")
        .effective_balance;
    let slash_count_needed = total_active_balance
        .checked_sub(required_balance)
        .expect("total active balance should be at least the required balance")
        / effective_balance
        + 1;

    let child_slot = parent_slot + 1;
    let child_proposer = parent_state
        .get_beacon_proposer_index(child_slot, &harness.chain.spec)
        .expect("should get child proposer") as u64;

    let (_, _, _, current_participation, _, _, _, _) = parent_state
        .mutable_validator_fields()
        .expect("parent state should have Altair validator fields");
    // Slash this epoch's timely-target voters (they count toward the current-epoch target balance),
    // excluding the child proposer, to drop target balance below the 2/3 justification threshold.
    let slash_indices = current_participation
        .iter()
        .enumerate()
        .filter_map(|(index, flags)| {
            flags
                .has_flag(TIMELY_TARGET_FLAG_INDEX)
                .ok()
                .and_then(|has_flag| has_flag.then_some(index as u64))
        })
        .filter(|index| *index != child_proposer)
        .take(slash_count_needed as usize)
        .collect::<Vec<_>>();

    assert_eq!(
        slash_indices.len(),
        slash_count_needed as usize,
        "should have enough current target attesters to slash"
    );

    inject_slashings(&harness, &slash_indices);

    harness.advance_slot();
    let child_root = harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (
        stored_parent_justified,
        stored_parent_finalized,
        stored_child_justified,
        stored_child_finalized,
        child_slot,
    ) = {
        let fork_choice = harness.chain.canonical_head.fork_choice_read_lock();
        let parent_block = fork_choice
            .get_block(&parent_root)
            .expect("parent should be in fork choice");
        let child_block = fork_choice
            .get_block(&child_root)
            .expect("child should be in fork choice");

        let parent_justified = parent_block
            .unrealized_justified_checkpoint
            .expect("parent should have unrealized justified checkpoint");
        let parent_finalized = parent_block
            .unrealized_finalized_checkpoint
            .expect("parent should have unrealized finalized checkpoint");

        assert_eq!(parent_block.slot, parent_slot);
        assert_eq!(parent_justified.epoch, parent_epoch);
        assert_eq!(parent_finalized.epoch.saturating_add(1u64), parent_epoch);
        assert_eq!(child_block.slot, parent_slot + 1);
        assert_eq!(child_block.slot.epoch(slots_per_epoch), parent_epoch);

        (
            parent_justified,
            parent_finalized,
            child_block
                .unrealized_justified_checkpoint
                .expect("child should have unrealized justified checkpoint"),
            child_block
                .unrealized_finalized_checkpoint
                .expect("child should have unrealized finalized checkpoint"),
            child_block.slot,
        )
    };

    let mut child_state = harness
        .chain
        .state_at_slot(child_slot, StateSkipConfig::WithStateRoots)
        .expect("should load child state");
    child_state
        .build_caches(&harness.chain.spec)
        .expect("should build child state caches");

    let slashed = child_state
        .validators()
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| validator.slashed.then_some(index as u64))
        .collect::<Vec<_>>();
    let child_total_active_balance = child_state
        .get_total_active_balance()
        .expect("should get child total active balance");
    let child_current_target_balance = child_state
        .progressive_balances_cache()
        .current_epoch_target_attesting_balance()
        .expect("should get child current target balance");
    let child_justification_and_finalization =
        per_epoch_processing::altair::process_justification_and_finalization(&child_state)
            .expect("should recompute child justification and finalization");
    let expected_child_justified =
        child_justification_and_finalization.current_justified_checkpoint();
    let expected_child_finalized = child_justification_and_finalization.finalized_checkpoint();

    assert_eq!(slashed, slash_indices);
    assert!(
        child_current_target_balance < ceil_two_thirds(child_total_active_balance),
        "slashings should reduce current target balance below the justification threshold"
    );
    assert_ne!(
        expected_child_justified, stored_parent_justified,
        "test setup should make the child justified checkpoint differ from the parent's"
    );
    assert_ne!(
        expected_child_finalized, stored_parent_finalized,
        "test setup should make the child finalized checkpoint differ from the parent's"
    );

    SameEpochSlashingChild {
        harness,
        stored_parent_justified,
        stored_parent_finalized,
        stored_child_justified,
        stored_child_finalized,
        expected_child_justified,
        expected_child_finalized,
        parent_epoch,
    }
}
