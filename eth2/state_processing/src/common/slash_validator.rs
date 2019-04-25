use crate::common::exit_validator;
use types::{BeaconStateError as Error, *};

/// Slash the validator with index ``index``.
///
/// Spec v0.5.1
pub fn slash_validator(
    state: &mut BeaconState,
    validator_index: usize,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);

    if (validator_index >= state.validator_registry.len())
        | (validator_index >= state.validator_balances.len())
    {
        return Err(BeaconStateError::UnknownValidator);
    }

    let validator = &state.validator_registry[validator_index];

    let effective_balance = state.get_effective_balance(validator_index, spec)?;

    // A validator that is withdrawn cannot be slashed.
    //
    // This constraint will be lifted in Phase 0.
    if state.slot
        >= validator
            .withdrawable_epoch
            .start_slot(spec.slots_per_epoch)
    {
        return Err(Error::ValidatorIsWithdrawable);
    }

    exit_validator(state, validator_index, spec)?;

    state.set_slashed_balance(
        current_epoch,
        state.get_slashed_balance(current_epoch, spec)? + effective_balance,
        spec,
    )?;

    let whistleblower_index =
        state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)?;
    let whistleblower_reward = effective_balance / spec.whistleblower_reward_quotient;

    safe_add_assign!(
        state.validator_balances[whistleblower_index as usize],
        whistleblower_reward
    );
    safe_sub_assign!(
        state.validator_balances[validator_index],
        whistleblower_reward
    );

    state.validator_registry[validator_index].slashed = true;

    state.validator_registry[validator_index].withdrawable_epoch =
        current_epoch + Epoch::from(spec.latest_slashed_exit_length);

    Ok(())
}
