use crate::common::update_progressive_balances_cache::update_progressive_balances_on_slashing;
use crate::{
    common::{decrease_balance, increase_balance, initiate_validator_exit},
    per_block_processing::errors::BlockProcessingError,
    ConsensusContext,
};
use safe_arith::SafeArith;
use std::cmp;
use types::{
    consts::altair::{PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    *,
};

/// Slash the validator with index `slashed_index`.
pub fn slash_validator<E: EthSpec>(
    state: &mut BeaconState<E>,
    slashed_index: usize,
    opt_whistleblower_index: Option<usize>,
    ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let epoch = state.current_epoch();
    let latest_block_slot = state.latest_block_header().slot;

    initiate_validator_exit(state, slashed_index, spec)?;

    let validator = state.get_validator_mut(slashed_index)?;
    validator.slashed = true;
    validator.withdrawable_epoch = cmp::max(
        validator.withdrawable_epoch,
        epoch.safe_add(E::EpochsPerSlashingsVector::to_u64())?,
    );
    let validator_effective_balance = validator.effective_balance;
    state.set_slashings(
        epoch,
        state
            .get_slashings(epoch)?
            .safe_add(validator_effective_balance)?,
    )?;

    decrease_balance(
        state,
        slashed_index,
        validator_effective_balance
            .safe_div(spec.min_slashing_penalty_quotient_for_state(state))?,
    )?;

    update_progressive_balances_on_slashing(state, slashed_index, validator_effective_balance)?;
    state
        .slashings_cache_mut()
        .record_validator_slashing(latest_block_slot, slashed_index)?;

    // Apply proposer and whistleblower rewards
    let proposer_index = ctxt.get_proposer_index(state, spec)? as usize;
    let whistleblower_index = opt_whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = validator_effective_balance
        .safe_div(spec.whistleblower_reward_quotient_for_state(state))?;
    let proposer_reward = match state {
        BeaconState::Base(_) => whistleblower_reward.safe_div(spec.proposer_reward_quotient)?,
        BeaconState::Altair(_)
        | BeaconState::Bellatrix(_)
        | BeaconState::Capella(_)
        | BeaconState::Deneb(_)
        | BeaconState::Electra(_)
        | BeaconState::EIP7732(_) => whistleblower_reward
            .safe_mul(PROPOSER_WEIGHT)?
            .safe_div(WEIGHT_DENOMINATOR)?,
    };

    // Ensure the whistleblower index is in the validator registry.
    if state.validators().get(whistleblower_index).is_none() {
        return Err(BeaconStateError::UnknownValidator(whistleblower_index).into());
    }

    increase_balance(state, proposer_index, proposer_reward)?;
    increase_balance(
        state,
        whistleblower_index,
        whistleblower_reward.safe_sub(proposer_reward)?,
    )?;

    Ok(())
}
