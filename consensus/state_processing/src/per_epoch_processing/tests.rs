#![cfg(test)]
use crate::per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards;
use crate::per_epoch_processing::process_epoch;
use crate::state_advance::complete_state_advance;
use beacon_chain::test_utils::BeaconChainHarness;
use beacon_chain::types::{EthSpec, MinimalEthSpec};
use integer_sqrt::IntegerSquareRoot;
use std::sync::Arc;
use types::consts::altair::{SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR};
use types::{BeaconState, ChainSpec, Epoch, ForkName, Slot};

#[tokio::test]
async fn runs_without_error() {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    harness.advance_slot();

    let target_slot =
        (MinimalEthSpec::genesis_epoch() + 4).end_slot(MinimalEthSpec::slots_per_epoch());

    let state = harness.get_current_state();
    harness
        .add_attested_blocks_at_slots(
            state,
            (1..target_slot.as_u64())
                .map(Slot::new)
                .collect::<Vec<_>>()
                .as_slice(),
            (0..8).collect::<Vec<_>>().as_slice(),
        )
        .await;
    let mut new_head_state = harness.get_current_state();

    process_epoch(&mut new_head_state, &harness.spec).unwrap();
}

/// Returns a Gloas state at epoch 1 and a copy of its spec with EIP-8198 at epoch 1 and half the
/// genesis slot duration.
fn gloas_state_with_half_slot_duration() -> (BeaconState<MinimalEthSpec>, ChainSpec, ChainSpec) {
    let spec = ForkName::Gloas.make_genesis_spec(MinimalEthSpec::default_spec());
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(Arc::new(spec.clone()))
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    let mut state = harness.get_current_state();
    let epoch_one = Epoch::new(1).start_slot(MinimalEthSpec::slots_per_epoch());
    complete_state_advance(&mut state, None, epoch_one, None, &spec).unwrap();
    state.build_caches(&spec).unwrap();
    let mut halved = spec.clone();
    halved.heze_fork_epoch = Some(state.current_epoch());
    halved.slot_duration_ms_eip8198 = spec.get_slot_duration_ms(Epoch::new(0)) / 2;
    (state, spec, halved)
}

#[tokio::test]
async fn churn_scales_with_the_slot_duration() {
    let (state, spec, halved) = gloas_state_with_half_slot_duration();
    let round = |churn: u64| churn - churn % spec.effective_balance_increment;
    let total_active_balance = state.get_total_active_balance().unwrap();
    let balance_churn = std::cmp::max(
        spec.min_per_epoch_churn_limit_electra,
        total_active_balance / spec.churn_limit_quotient_gloas,
    );
    let activation_churn = std::cmp::min(
        spec.max_per_epoch_activation_churn_limit_gloas,
        balance_churn,
    );
    let consolidation_churn = total_active_balance / spec.consolidation_churn_limit_quotient;

    assert_eq!(
        state.get_exit_churn_limit(&spec).unwrap(),
        round(balance_churn)
    );
    assert_eq!(
        state.get_exit_churn_limit(&halved).unwrap(),
        round(balance_churn / 2)
    );
    assert_eq!(
        state.get_activation_exit_churn_limit(&halved).unwrap(),
        round(activation_churn / 2)
    );
    assert_eq!(
        state.get_consolidation_churn_limit(&halved).unwrap(),
        round(consolidation_churn / 2)
    );
}

#[tokio::test]
async fn sync_aggregate_rewards_scale_with_the_slot_duration() {
    let (state, spec, halved) = gloas_state_with_half_slot_duration();
    let total_active_balance = state.get_total_active_balance().unwrap();
    let participant_reward = |slot_duration_ratio_half: bool| {
        let mut base_reward_per_increment =
            spec.effective_balance_increment * spec.base_reward_factor;
        if slot_duration_ratio_half {
            base_reward_per_increment /= 2;
        }
        base_reward_per_increment /= total_active_balance.integer_sqrt();
        base_reward_per_increment
            * (total_active_balance / spec.effective_balance_increment)
            * SYNC_REWARD_WEIGHT
            / WEIGHT_DENOMINATOR
            / MinimalEthSpec::slots_per_epoch()
            / MinimalEthSpec::sync_committee_size() as u64
    };

    assert_eq!(
        compute_sync_aggregate_rewards(&state, &spec).unwrap().0,
        participant_reward(false)
    );
    assert_eq!(
        compute_sync_aggregate_rewards(&state, &halved).unwrap().0,
        participant_reward(true)
    );
}

#[cfg(not(debug_assertions))]
mod release_tests {
    use super::*;
    use crate::{
        EpochProcessingError, GloasVerificationContext, SlotProcessingError,
        per_slot_processing::per_slot_processing,
    };
    use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
    use std::sync::Arc;
    use types::{Epoch, ForkName, InconsistentFork, MainnetEthSpec};

    #[tokio::test]
    async fn altair_state_on_base_fork() {
        let mut spec = MainnetEthSpec::default_spec();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        // The Altair fork happens at epoch 1.
        spec.altair_fork_epoch = Some(Epoch::new(1));

        let altair_state = {
            let harness = BeaconChainHarness::builder(MainnetEthSpec)
                .spec(Arc::new(spec.clone()))
                .deterministic_keypairs(8)
                .fresh_ephemeral_store()
                .build();

            harness.advance_slot();

            harness
                .extend_chain(
                    // Build out enough blocks so we get an Altair block at the very end of an epoch.
                    (slots_per_epoch * 2 - 1) as usize,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;

            harness.get_current_state()
        };

        // Pre-conditions for a valid test.
        assert_eq!(altair_state.fork_name(&spec).unwrap(), ForkName::Altair);
        assert_eq!(
            altair_state.slot(),
            altair_state.current_epoch().end_slot(slots_per_epoch)
        );

        // Check the state is valid before starting this test.
        process_epoch(&mut altair_state.clone(), &spec)
            .expect("state passes intial epoch processing");
        per_slot_processing(
            &mut altair_state.clone(),
            None,
            GloasVerificationContext::FullVerification,
            &spec,
        )
        .expect("state passes intial slot processing");

        // Modify the spec so altair never happens.
        spec.altair_fork_epoch = None;

        let expected_err = InconsistentFork {
            fork_at_slot: ForkName::Base,
            object_fork: ForkName::Altair,
        };

        assert_eq!(altair_state.fork_name(&spec), Err(expected_err));
        assert_eq!(
            process_epoch(&mut altair_state.clone(), &spec),
            Err(EpochProcessingError::InconsistentStateFork(expected_err))
        );
        assert_eq!(
            per_slot_processing(
                &mut altair_state.clone(),
                None,
                GloasVerificationContext::FullVerification,
                &spec
            ),
            Err(SlotProcessingError::InconsistentStateFork(expected_err))
        );
    }

    #[tokio::test]
    async fn base_state_on_altair_fork() {
        let mut spec = MainnetEthSpec::default_spec();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        // The Altair fork never happens.
        spec.altair_fork_epoch = None;

        let base_state = {
            let harness = BeaconChainHarness::builder(MainnetEthSpec)
                .spec(Arc::new(spec.clone()))
                .deterministic_keypairs(8)
                .fresh_ephemeral_store()
                .build();

            harness.advance_slot();

            harness
                .extend_chain(
                    // Build out enough blocks so we get a block at the very end of an epoch.
                    (slots_per_epoch * 2 - 1) as usize,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;

            harness.get_current_state()
        };

        // Pre-conditions for a valid test.
        assert_eq!(base_state.fork_name(&spec).unwrap(), ForkName::Base);
        assert_eq!(
            base_state.slot(),
            base_state.current_epoch().end_slot(slots_per_epoch)
        );

        // Check the state is valid before starting this test.
        process_epoch(&mut base_state.clone(), &spec)
            .expect("state passes intial epoch processing");
        per_slot_processing(
            &mut base_state.clone(),
            None,
            GloasVerificationContext::FullVerification,
            &spec,
        )
        .expect("state passes intial slot processing");

        // Modify the spec so Altair happens at the first epoch.
        spec.altair_fork_epoch = Some(Epoch::new(1));

        let expected_err = InconsistentFork {
            fork_at_slot: ForkName::Altair,
            object_fork: ForkName::Base,
        };

        assert_eq!(base_state.fork_name(&spec), Err(expected_err));
        assert_eq!(
            process_epoch(&mut base_state.clone(), &spec),
            Err(EpochProcessingError::InconsistentStateFork(expected_err))
        );
        assert_eq!(
            per_slot_processing(
                &mut base_state.clone(),
                None,
                GloasVerificationContext::FullVerification,
                &spec
            ),
            Err(SlotProcessingError::InconsistentStateFork(expected_err))
        );
    }
}
