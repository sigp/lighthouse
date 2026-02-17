use crate::common::decrease_balance;
use crate::per_block_processing::builder::{
    convert_builder_index_to_validator_index, convert_validator_index_to_builder_index,
    is_builder_index,
};
use crate::per_block_processing::errors::BlockProcessingError;
use milhouse::List;
use safe_arith::{SafeArith, SafeArithIter};
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BeaconState, BeaconStateError, ChainSpec, EthSpec, ExecPayload,
    ExpectedWithdrawals, ExpectedWithdrawalsCapella, ExpectedWithdrawalsElectra,
    ExpectedWithdrawalsGloas, Validator, Withdrawal, Withdrawals,
};

/// Compute the next batch of withdrawals which should be included in a block.
///
/// https://ethereum.github.io/consensus-specs/specs/gloas/beacon-chain/#modified-get_expected_withdrawals
#[allow(clippy::type_complexity)]
pub fn get_expected_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<ExpectedWithdrawals<E>, BlockProcessingError> {
    let mut withdrawal_index = state.next_withdrawal_index()?;
    let mut withdrawals = Vec::<Withdrawal>::with_capacity(E::max_withdrawals_per_payload());

    // [New in Gloas:EIP7732]
    // Get builder withdrawals
    let processed_builder_withdrawals_count =
        get_builder_withdrawals(state, &mut withdrawal_index, &mut withdrawals)?;

    // [New in Electra:EIP7251]
    // Get partial withdrawals.
    let processed_partial_withdrawals_count =
        get_pending_partial_withdrawals(state, &mut withdrawal_index, &mut withdrawals, spec)?;

    // [New in Gloas:EIP7732]
    // Get builders sweep withdrawals
    let processed_builders_sweep_count =
        get_builders_sweep_withdrawals(state, &mut withdrawal_index, &mut withdrawals)?;

    // Get validators sweep withdrawals
    let processed_sweep_withdrawals_count =
        get_validators_sweep_withdrawals(state, &mut withdrawal_index, &mut withdrawals, spec)?;

    let withdrawals = withdrawals
        .try_into()
        .map_err(BlockProcessingError::SszTypesError)?;

    let fork_name = state.fork_name_unchecked();
    if fork_name.gloas_enabled() {
        Ok(ExpectedWithdrawals::Gloas(ExpectedWithdrawalsGloas {
            withdrawals,
            processed_builder_withdrawals_count: processed_builder_withdrawals_count
                .ok_or(BlockProcessingError::IncorrectExpectedWithdrawalsVariant)?,
            processed_partial_withdrawals_count: processed_partial_withdrawals_count
                .ok_or(BlockProcessingError::IncorrectExpectedWithdrawalsVariant)?,
            processed_builders_sweep_count: processed_builders_sweep_count
                .ok_or(BlockProcessingError::IncorrectExpectedWithdrawalsVariant)?,
            processed_sweep_withdrawals_count,
        }))
    } else if fork_name.electra_enabled() {
        Ok(ExpectedWithdrawals::Electra(ExpectedWithdrawalsElectra {
            withdrawals,
            processed_partial_withdrawals_count: processed_partial_withdrawals_count
                .ok_or(BlockProcessingError::IncorrectExpectedWithdrawalsVariant)?,
            processed_sweep_withdrawals_count,
        }))
    } else {
        Ok(ExpectedWithdrawals::Capella(ExpectedWithdrawalsCapella {
            withdrawals,
            processed_sweep_withdrawals_count,
        }))
    }
}

pub fn get_builder_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal_index: &mut u64,
    withdrawals: &mut Vec<Withdrawal>,
) -> Result<Option<u64>, BlockProcessingError> {
    let Ok(builder_pending_withdrawals) = state.builder_pending_withdrawals() else {
        // Pre-Gloas, nothing to do.
        return Ok(None);
    };

    let withdrawals_limit = E::max_withdrawals_per_payload().safe_sub(1)?;

    block_verify!(
        withdrawals.len() <= withdrawals_limit,
        BlockProcessingError::WithdrawalsLimitExceeded {
            limit: withdrawals_limit,
            prior_withdrawals: withdrawals.len()
        }
    );

    let mut processed_count = 0;
    for withdrawal in builder_pending_withdrawals {
        let has_reached_limit = withdrawals.len() == withdrawals_limit;

        if has_reached_limit {
            break;
        }

        let builder_index = withdrawal.builder_index;

        withdrawals.push(Withdrawal {
            index: *withdrawal_index,
            validator_index: convert_builder_index_to_validator_index(builder_index),
            address: withdrawal.fee_recipient,
            amount: withdrawal.amount,
        });
        withdrawal_index.safe_add_assign(1)?;
        processed_count.safe_add_assign(1)?;
    }
    Ok(Some(processed_count))
}

pub fn get_pending_partial_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal_index: &mut u64,
    withdrawals: &mut Vec<Withdrawal>,
    spec: &ChainSpec,
) -> Result<Option<u64>, BlockProcessingError> {
    let Ok(pending_partial_withdrawals) = state.pending_partial_withdrawals() else {
        // Pre-Electra nothing to do.
        return Ok(None);
    };
    let epoch = state.current_epoch();

    let withdrawals_limit = std::cmp::min(
        withdrawals
            .len()
            .safe_add(spec.max_pending_partials_per_withdrawals_sweep as usize)?,
        E::max_withdrawals_per_payload().safe_sub(1)?,
    );

    block_verify!(
        withdrawals.len() <= withdrawals_limit,
        BlockProcessingError::WithdrawalsLimitExceeded {
            limit: withdrawals_limit,
            prior_withdrawals: withdrawals.len()
        }
    );

    let mut processed_count = 0;
    for withdrawal in pending_partial_withdrawals {
        let is_withdrawable = withdrawal.withdrawable_epoch <= epoch;
        let has_reached_limit = withdrawals.len() >= withdrawals_limit;

        if !is_withdrawable || has_reached_limit {
            break;
        }

        let validator_index = withdrawal.validator_index;
        let validator = state.get_validator(validator_index as usize)?;
        let balance = get_balance_after_withdrawals(state, validator_index, withdrawals)?;

        if is_eligible_for_partial_withdrawals(validator, balance, spec) {
            let withdrawal_amount = std::cmp::min(
                balance.safe_sub(spec.min_activation_balance)?,
                withdrawal.amount,
            );
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec)
                    .ok_or(BeaconStateError::NonExecutionAddressWithdrawalCredential)?,
                amount: withdrawal_amount,
            });
            withdrawal_index.safe_add_assign(1)?;
        }
        processed_count.safe_add_assign(1)?;
    }

    Ok(Some(processed_count))
}

/// Get withdrawals from the builders sweep.
///
/// This function iterates through builders starting from `next_withdrawal_builder_index`
/// and adds withdrawals for builders whose withdrawable_epoch has been reached and have balance.
///
/// https://ethereum.github.io/consensus-specs/specs/gloas/beacon-chain/#new-get_builders_sweep_withdrawals
pub fn get_builders_sweep_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal_index: &mut u64,
    withdrawals: &mut Vec<Withdrawal>,
) -> Result<Option<u64>, BlockProcessingError> {
    let Ok(builders) = state.builders() else {
        // Pre-Gloas, nothing to do.
        return Ok(None);
    };

    if builders.is_empty() {
        return Ok(Some(0));
    }

    let epoch = state.current_epoch();
    let builders_limit = std::cmp::min(builders.len(), E::max_builders_per_withdrawals_sweep());

    let withdrawals_limit = E::max_withdrawals_per_payload().safe_sub(1)?;

    block_verify!(
        withdrawals.len() <= withdrawals_limit,
        BlockProcessingError::WithdrawalsLimitExceeded {
            limit: withdrawals_limit,
            prior_withdrawals: withdrawals.len()
        }
    );

    let mut processed_count: u64 = 0;
    let mut builder_index = state.next_withdrawal_builder_index()?;

    for _ in 0..builders_limit {
        if withdrawals.len() >= withdrawals_limit {
            break;
        }

        let builder = builders
            .get(builder_index as usize)
            .ok_or(BeaconStateError::UnknownBuilder(builder_index))?;

        if builder.withdrawable_epoch <= epoch && builder.balance > 0 {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index: convert_builder_index_to_validator_index(builder_index),
                address: builder.execution_address,
                amount: builder.balance,
            });
            withdrawal_index.safe_add_assign(1)?;
        }

        builder_index = builder_index.safe_add(1)?.safe_rem(builders.len() as u64)?;
        processed_count.safe_add_assign(1)?;
    }

    Ok(Some(processed_count))
}

/// Get withdrawals from the validator sweep.
///
/// This function iterates through validators starting from `next_withdrawal_validator_index`
/// and adds full or partial withdrawals for eligible validators.
///
/// https://ethereum.github.io/consensus-specs/specs/capella/beacon-chain/#new-get_validators_sweep_withdrawals
pub fn get_validators_sweep_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal_index: &mut u64,
    withdrawals: &mut Vec<Withdrawal>,
    spec: &ChainSpec,
) -> Result<u64, BlockProcessingError> {
    let epoch = state.current_epoch();
    let fork_name = state.fork_name_unchecked();
    let mut validator_index = state.next_withdrawal_validator_index()?;
    let validators_limit = std::cmp::min(
        state.validators().len() as u64,
        spec.max_validators_per_withdrawals_sweep,
    );
    let withdrawals_limit = E::max_withdrawals_per_payload();

    // There must be at least one space reserved for validator sweep withdrawals
    block_verify!(
        withdrawals.len() < withdrawals_limit,
        BlockProcessingError::WithdrawalsLimitExceeded {
            limit: withdrawals_limit,
            prior_withdrawals: withdrawals.len()
        }
    );

    let mut processed_count: u64 = 0;

    for _ in 0..validators_limit {
        if withdrawals.len() >= withdrawals_limit {
            break;
        }

        let validator = state.get_validator(validator_index as usize)?;
        let balance = get_balance_after_withdrawals(state, validator_index, withdrawals)?;

        if validator.is_fully_withdrawable_validator(balance, epoch, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance,
            });
            withdrawal_index.safe_add_assign(1)?;
        } else if validator.is_partially_withdrawable_validator(balance, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance.safe_sub(validator.get_max_effective_balance(spec, fork_name))?,
            });
            withdrawal_index.safe_add_assign(1)?;
        }

        validator_index = validator_index
            .safe_add(1)?
            .safe_rem(state.validators().len() as u64)?;
        processed_count.safe_add_assign(1)?;
    }

    Ok(processed_count)
}

pub fn get_balance_after_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    validator_index: u64,
    withdrawals: &[Withdrawal],
) -> Result<u64, BeaconStateError> {
    let withdrawn = withdrawals
        .iter()
        .filter(|withdrawal| withdrawal.validator_index == validator_index)
        .map(|withdrawal| withdrawal.amount)
        .safe_sum()?;
    state
        .get_balance(validator_index as usize)?
        .safe_sub(withdrawn)
        .map_err(Into::into)
}

fn is_eligible_for_partial_withdrawals(
    validator: &Validator,
    balance: u64,
    spec: &ChainSpec,
) -> bool {
    let has_sufficient_effective_balance =
        validator.effective_balance >= spec.min_activation_balance;
    let has_excess_balance = balance > spec.min_activation_balance;
    validator.exit_epoch == spec.far_future_epoch
        && has_sufficient_effective_balance
        && has_excess_balance
}

fn update_next_withdrawal_index<E: EthSpec>(
    state: &mut BeaconState<E>,
    withdrawals: &Withdrawals<E>,
) -> Result<(), BlockProcessingError> {
    // Update the next withdrawal index if this block contained withdrawals
    if let Some(latest_withdrawal) = withdrawals.last() {
        *state.next_withdrawal_index_mut()? = latest_withdrawal.index.safe_add(1)?;
    }
    Ok(())
}

fn update_payload_expected_withdrawals<E: EthSpec>(
    state: &mut BeaconState<E>,
    withdrawals: &Withdrawals<E>,
) -> Result<(), BlockProcessingError> {
    *state.payload_expected_withdrawals_mut()? = List::new(withdrawals.to_vec())?;
    Ok(())
}

fn update_builder_pending_withdrawals<E: EthSpec>(
    state: &mut BeaconState<E>,
    processed_builder_withdrawals_count: u64,
) -> Result<(), BlockProcessingError> {
    state
        .builder_pending_withdrawals_mut()?
        .pop_front(processed_builder_withdrawals_count as usize)?;
    Ok(())
}

fn update_pending_partial_withdrawals<E: EthSpec>(
    state: &mut BeaconState<E>,
    processed_partial_withdrawals_count: u64,
) -> Result<(), BlockProcessingError> {
    state
        .pending_partial_withdrawals_mut()?
        .pop_front(processed_partial_withdrawals_count as usize)?;
    Ok(())
}

fn update_next_withdrawal_builder_index<E: EthSpec>(
    state: &mut BeaconState<E>,
    processed_builders_sweep_count: u64,
) -> Result<(), BlockProcessingError> {
    if !state.builders()?.is_empty() {
        // Update the next builder index to start the next withdrawal sweep
        let next_index = state
            .next_withdrawal_builder_index()?
            .safe_add(processed_builders_sweep_count)?;
        let next_builder_index = next_index.safe_rem(state.builders()?.len() as u64)?;
        *state.next_withdrawal_builder_index_mut()? = next_builder_index;
    }
    Ok(())
}

fn update_next_withdrawal_validator_index<E: EthSpec>(
    state: &mut BeaconState<E>,
    withdrawals: &Withdrawals<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Update the next validator index to start the next withdrawal sweep
    if withdrawals.len() == E::max_withdrawals_per_payload() {
        // Next sweep starts after the latest withdrawal's validator index
        let latest_withdrawal = withdrawals
            .last()
            .ok_or(BlockProcessingError::MissingLastWithdrawal)?;
        let next_validator_index = latest_withdrawal
            .validator_index
            .safe_add(1)?
            .safe_rem(state.validators().len() as u64)?;
        *state.next_withdrawal_validator_index_mut()? = next_validator_index;
    } else {
        // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        let next_validator_index = state
            .next_withdrawal_validator_index()?
            .safe_add(spec.max_validators_per_withdrawals_sweep)?
            .safe_rem(state.validators().len() as u64)?;
        *state.next_withdrawal_validator_index_mut()? = next_validator_index;
    }
    Ok(())
}

pub fn apply_withdrawals<E: EthSpec>(
    state: &mut BeaconState<E>,
    withdrawals: &Withdrawals<E>,
) -> Result<(), BlockProcessingError> {
    for withdrawal in withdrawals {
        if state.fork_name_unchecked().gloas_enabled()
            && is_builder_index(withdrawal.validator_index)
        {
            let builder_index =
                convert_validator_index_to_builder_index(withdrawal.validator_index);
            let builder = state
                .builders_mut()?
                .get_mut(builder_index as usize)
                .ok_or(BeaconStateError::UnknownBuilder(builder_index))?;
            builder.balance = builder.balance.saturating_sub(withdrawal.amount);
        } else {
            decrease_balance(
                state,
                withdrawal.validator_index as usize,
                withdrawal.amount,
            )?;
        }
    }
    Ok(())
}

pub mod capella_electra {
    use super::*;

    /// Apply withdrawals to the state.
    pub fn process_withdrawals<E: EthSpec, Payload: AbstractExecPayload<E>>(
        state: &mut BeaconState<E>,
        payload: Payload::Ref<'_>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        let expected_withdrawals = get_expected_withdrawals(state, spec)?;

        let expected_root = expected_withdrawals.withdrawals().tree_hash_root();
        let withdrawals_root = payload.withdrawals_root()?;
        if expected_root != withdrawals_root {
            return Err(BlockProcessingError::WithdrawalsRootMismatch {
                expected: expected_root,
                found: withdrawals_root,
            });
        }

        // Apply expected withdrawals.
        apply_withdrawals(state, expected_withdrawals.withdrawals())?;

        // [Common] Update withdrawals fields in the state
        update_next_withdrawal_index(state, expected_withdrawals.withdrawals())?;

        // [New in Electra:EIP7251]
        if let Ok(processed_partial_withdrawals_count) =
            expected_withdrawals.processed_partial_withdrawals_count()
        {
            update_pending_partial_withdrawals(state, processed_partial_withdrawals_count)?;
        }

        // [Common from Capella]
        update_next_withdrawal_validator_index(state, expected_withdrawals.withdrawals(), spec)?;

        Ok(())
    }
}

pub mod gloas {
    use super::*;

    /// Apply withdrawals to the state.
    pub fn process_withdrawals<E: EthSpec>(
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        if !state.is_parent_block_full() {
            return Ok(());
        }

        let ExpectedWithdrawals::Gloas(ExpectedWithdrawalsGloas {
            withdrawals,
            processed_builder_withdrawals_count,
            processed_partial_withdrawals_count,
            processed_builders_sweep_count,
            processed_sweep_withdrawals_count: _,
        }) = get_expected_withdrawals(state, spec)?
        else {
            return Err(BlockProcessingError::IncorrectExpectedWithdrawalsVariant);
        };

        // Apply expected withdrawals.
        apply_withdrawals(state, &withdrawals)?;

        // [Common] Update withdrawals fields in the state
        update_next_withdrawal_index(state, &withdrawals)?;

        // [New in Gloas:EIP7732]
        update_payload_expected_withdrawals(state, &withdrawals)?;

        // [New in Gloas:EIP7732]
        update_builder_pending_withdrawals(state, processed_builder_withdrawals_count)?;

        // [Common from Electra]
        update_pending_partial_withdrawals(state, processed_partial_withdrawals_count)?;

        // [New in Gloas:EIP7732]
        update_next_withdrawal_builder_index(state, processed_builders_sweep_count)?;

        // [Common from Capella]
        update_next_withdrawal_validator_index(state, &withdrawals, spec)?;

        Ok(())
    }
}
