use crate::common::{decrease_balance, increase_balance, initiate_validator_exit};
use safe_arith::SafeArith;
use std::cmp;
use types::{
    consts::altair::{PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    BeaconStateError as Error, *,
};

/// Slash the validator with index `slashed_index`.
pub fn slash_validator<T: EthSpec>(
    state: &mut BeaconState<T>,
    slashed_index: usize,
    opt_whistleblower_index: Option<usize>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = state.current_epoch();

    initiate_validator_exit(state, slashed_index, spec)?;

    let validator = state.get_validator_mut(slashed_index)?;
    validator.slashed = true;
    validator.withdrawable_epoch = cmp::max(
        validator.withdrawable_epoch,
        epoch.safe_add(T::EpochsPerSlashingsVector::to_u64())?,
    );
    let validator_effective_balance = validator.effective_balance;
    state.set_slashings(
        epoch,
        state
            .get_slashings(epoch)?
            .safe_add(validator_effective_balance)?,
    )?;

    let min_slashing_penalty_quotient = match state {
        BeaconState::Base(_) => spec.min_slashing_penalty_quotient,
        BeaconState::Altair(_) => spec.min_slashing_penalty_quotient_altair,
    };
    decrease_balance(
        state,
        slashed_index,
        validator_effective_balance.safe_div(min_slashing_penalty_quotient)?,
    )?;

    // Apply proposer and whistleblower rewards
    let proposer_index = state.get_beacon_proposer_index(state.slot(), spec)?;
    let whistleblower_index = opt_whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward =
        validator_effective_balance.safe_div(spec.whistleblower_reward_quotient)?;
    let proposer_reward = match state {
        BeaconState::Base(_) => whistleblower_reward.safe_div(spec.proposer_reward_quotient)?,
        BeaconState::Altair(_) => whistleblower_reward
            .safe_mul(PROPOSER_WEIGHT)?
            .safe_div(WEIGHT_DENOMINATOR)?,
    };

    // Ensure the whistleblower index is in the validator registry.
    if state.validators().get(whistleblower_index).is_none() {
        return Err(BeaconStateError::UnknownValidator(whistleblower_index));
    }

    increase_balance(state, proposer_index, proposer_reward)?;
    increase_balance(
        state,
        whistleblower_index,
        whistleblower_reward.safe_sub(proposer_reward)?,
    )?;

    Ok(())
}
