use super::errors::BlockProcessingError;
use super::get_expected_withdrawals;
use crate::common::decrease_balance;
use milhouse::List;
use safe_arith::SafeArith;
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BeaconState, BuilderPendingWithdrawal, ChainSpec, EthSpec, ExecPayload,
    Withdrawals,
};

/// Check if a builder payment is withdrawable.
/// A builder payment is withdrawable if the builder is not slashed or
/// the builder's withdrawable epoch has been reached.
pub fn is_builder_payment_withdrawable<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal: &BuilderPendingWithdrawal,
) -> Result<bool, BlockProcessingError> {
    let builder = state.get_validator(withdrawal.builder_index as usize)?;
    let current_epoch = state.current_epoch();

    Ok(builder.withdrawable_epoch >= current_epoch || !builder.slashed)
}

fn process_withdrawals_common<E: EthSpec>(
    state: &mut BeaconState<E>,
    expected_withdrawals: Withdrawals<E>,
    partial_withdrawals_count: Option<usize>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    match state {
        BeaconState::Capella(_)
        | BeaconState::Deneb(_)
        | BeaconState::Electra(_)
        | BeaconState::Fulu(_)
        | BeaconState::Gloas(_) => {
            // Update pending partial withdrawals [New in Electra:EIP7251]
            if let Some(partial_withdrawals_count) = partial_withdrawals_count {
                state
                    .pending_partial_withdrawals_mut()?
                    .pop_front(partial_withdrawals_count)?;
            }

            // Update the next withdrawal index if this block contained withdrawals
            if let Some(latest_withdrawal) = expected_withdrawals.last() {
                *state.next_withdrawal_index_mut()? = latest_withdrawal.index.safe_add(1)?;

                // Update the next validator index to start the next withdrawal sweep
                if expected_withdrawals.len() == E::max_withdrawals_per_payload() {
                    // Next sweep starts after the latest withdrawal's validator index
                    let next_validator_index = latest_withdrawal
                        .validator_index
                        .safe_add(1)?
                        .safe_rem(state.validators().len() as u64)?;
                    *state.next_withdrawal_validator_index_mut()? = next_validator_index;
                }
            }

            // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
            if expected_withdrawals.len() != E::max_withdrawals_per_payload() {
                let next_validator_index = state
                    .next_withdrawal_validator_index()?
                    .safe_add(spec.max_validators_per_withdrawals_sweep)?
                    .safe_rem(state.validators().len() as u64)?;
                *state.next_withdrawal_validator_index_mut()? = next_validator_index;
            }

            Ok(())
        }
        // these shouldn't even be encountered but they're here for completeness
        BeaconState::Base(_) | BeaconState::Altair(_) | BeaconState::Bellatrix(_) => Ok(()),
    }
}

pub mod capella {
    use super::*;
    /// Apply withdrawals to the state.
    pub fn process_withdrawals<E: EthSpec, Payload: AbstractExecPayload<E>>(
        state: &mut BeaconState<E>,
        payload: Payload::Ref<'_>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        // check if capella enabled because this function will run on the merge block where the fork is technically still Bellatrix
        if state.fork_name_unchecked().capella_enabled() {
            let (expected_withdrawals, _, partial_withdrawals_count) =
                get_expected_withdrawals(state, spec)?;

            let expected_root = expected_withdrawals.tree_hash_root();
            let withdrawals_root = payload.withdrawals_root()?;
            if expected_root != withdrawals_root {
                return Err(BlockProcessingError::WithdrawalsRootMismatch {
                    expected: expected_root,
                    found: withdrawals_root,
                });
            }

            for withdrawal in expected_withdrawals.iter() {
                decrease_balance(
                    state,
                    withdrawal.validator_index as usize,
                    withdrawal.amount,
                )?;
            }

            process_withdrawals_common(state, expected_withdrawals, partial_withdrawals_count, spec)
        } else {
            // these shouldn't even be encountered but they're here for completeness
            Ok(())
        }
    }
}
pub mod gloas {
    use super::*;

    // TODO(EIP-7732): Add comprehensive tests for Gloas `process_withdrawals`:
    // Similar to Capella version, these will be tested via:
    // 1. EF consensus-spec tests in `testing/ef_tests/src/cases/operations.rs`
    // 2. Integration tests via full block processing
    // These tests would currently fail due to incomplete Gloas block structure as mentioned here, so we will implement them after block and payload processing is in a good state.
    // https://github.com/sigp/lighthouse/pull/8273
    /// Apply withdrawals to the state.
    pub fn process_withdrawals<E: EthSpec>(
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        if !state.is_parent_block_full() {
            return Ok(());
        }

        let (expected_withdrawals, builder_withdrawals_count, partial_withdrawals_count) =
            get_expected_withdrawals(state, spec)?;

        *state.latest_withdrawals_root_mut()? = expected_withdrawals.tree_hash_root();

        for withdrawal in expected_withdrawals.iter() {
            decrease_balance(
                state,
                withdrawal.validator_index as usize,
                withdrawal.amount,
            )?;
        }

        if let (Ok(builder_pending_withdrawals), Some(builder_count)) = (
            state.builder_pending_withdrawals(),
            builder_withdrawals_count,
        ) {
            let mut updated_builder_withdrawals =
                Vec::with_capacity(E::builder_pending_withdrawals_limit());

            for (i, withdrawal) in builder_pending_withdrawals.iter().enumerate() {
                if i < builder_count {
                    if !is_builder_payment_withdrawable(state, withdrawal)? {
                        updated_builder_withdrawals.push(withdrawal.clone());
                    }
                } else {
                    updated_builder_withdrawals.push(withdrawal.clone());
                }
            }

            *state.builder_pending_withdrawals_mut()? = List::new(updated_builder_withdrawals)?;
        }

        process_withdrawals_common(state, expected_withdrawals, partial_withdrawals_count, spec)?;

        Ok(())
    }
}
