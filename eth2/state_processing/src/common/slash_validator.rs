use crate::common::initiate_validator_exit;
use std::cmp;
use types::{BeaconStateError as Error, *};

/// Slash the validator with index ``index``.
///
/// Spec v0.8.0
pub fn slash_validator<T: EthSpec>(
    state: &mut BeaconState<T>,
    slashed_index: usize,
    opt_whistleblower_index: Option<usize>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if slashed_index >= state.validators.len() || slashed_index >= state.balances.len() {
        return Err(BeaconStateError::UnknownValidator);
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
        state.get_slashings(epoch)? + validator_effective_balance,
    )?;
    safe_sub_assign!(
        state.balances[slashed_index],
        validator_effective_balance / spec.min_slashing_penalty_quotient
    );

    // Apply proposer and whistleblower rewards
    let proposer_index =
        state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)?;
    let whistleblower_index = opt_whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = validator_effective_balance / spec.whistleblower_reward_quotient;
    let proposer_reward = whistleblower_reward / spec.proposer_reward_quotient;

    safe_add_assign!(state.balances[proposer_index], proposer_reward);
    safe_add_assign!(
        state.balances[whistleblower_index],
        whistleblower_reward.saturating_sub(proposer_reward)
    );

    Ok(())
}
