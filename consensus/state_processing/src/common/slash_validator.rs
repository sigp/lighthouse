use crate::common::{decrease_balance, increase_balance, initiate_validator_exit};
use safe_arith::SafeArith;
use std::cmp;
use types::{BeaconStateError as Error, *};

/// Slash the validator with index ``index``.
///
/// Spec v0.11.1
pub fn slash_validator<T: EthSpec>(
    state: &mut BeaconState<T>,
    slashed_index: usize,
    opt_whistleblower_index: Option<usize>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if slashed_index >= state.validators.len() || slashed_index >= state.balances.len() {
        return Err(BeaconStateError::UnknownValidator(slashed_index as u64));
    }

    let epoch = state.current_epoch();

    initiate_validator_exit(state, slashed_index, spec)?;

    state.validators[slashed_index].slashed = true;
    state.validators[slashed_index].withdrawable_epoch = cmp::max(
        state.validators[slashed_index].withdrawable_epoch,
        epoch + Epoch::from(T::EpochsPerSlashingsVector::to_u64()),
    );
    let validator_effective_balance = state.get_effective_balance(slashed_index, spec)?;
    state.set_slashings(
        epoch,
        state
            .get_slashings(epoch)?
            .safe_add(validator_effective_balance)?,
    )?;
    decrease_balance(
        state,
        slashed_index,
        validator_effective_balance.safe_div(spec.min_slashing_penalty_quotient)?,
    );

    // Apply proposer and whistleblower rewards
    let proposer_index = state.get_beacon_proposer_index(state.slot, spec)?;
    let whistleblower_index = opt_whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward =
        validator_effective_balance.safe_div(spec.whistleblower_reward_quotient)?;
    let proposer_reward = whistleblower_reward.safe_div(spec.proposer_reward_quotient)?;

    increase_balance(state, proposer_index, proposer_reward)?;
    increase_balance(
        state,
        whistleblower_index,
        whistleblower_reward.safe_sub(proposer_reward)?,
    )?;

    Ok(())
}
