use crate::common::initiate_validator_exit;
use types::{BeaconStateError as Error, *};

/// Slash the validator with index ``index``.
///
/// Spec v0.6.1
pub fn slash_validator<T: EthSpec>(
    state: &mut BeaconState<T>,
    slashed_index: usize,
    opt_whistleblower_index: Option<usize>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if slashed_index >= state.validator_registry.len() || slashed_index >= state.balances.len() {
        return Err(BeaconStateError::UnknownValidator);
    }

    let current_epoch = state.current_epoch();

    initiate_validator_exit(state, slashed_index, spec)?;

    state.validator_registry[slashed_index].slashed = true;
    state.validator_registry[slashed_index].withdrawable_epoch =
        current_epoch + Epoch::from(T::latest_slashed_exit_length());
    let slashed_balance = state.get_effective_balance(slashed_index, spec)?;

    state.set_slashed_balance(
        current_epoch,
        state.get_slashed_balance(current_epoch)? + slashed_balance,
    )?;

    let proposer_index =
        state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)?;
    let whistleblower_index = opt_whistleblower_index.unwrap_or(proposer_index);
    let whistleblowing_reward = slashed_balance / spec.whistleblowing_reward_quotient;
    let proposer_reward = whistleblowing_reward / spec.proposer_reward_quotient;

    safe_add_assign!(state.balances[proposer_index], proposer_reward);
    safe_add_assign!(
        state.balances[whistleblower_index],
        whistleblowing_reward - proposer_reward
    );
    safe_sub_assign!(state.balances[slashed_index], whistleblowing_reward);

    Ok(())
}
