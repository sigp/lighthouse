use crate::per_epoch_processing::{
    process_registry_updates, process_slashings, EpochProcessingSummary, Error,
};
use itertools::izip;
use safe_arith::SafeArith;
use std::cmp::{max, min};
use types::{
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
    BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, ParticipationFlags,
};

struct StateContext {
    previous_epoch: Epoch,
    current_epoch: Epoch,
    next_epoch: Epoch,
    is_in_inactivity_leak: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ValidatorInfo {
    pub effective_balance: u64,
    pub base_reward: u64,
    pub is_eligible: bool,
    pub is_slashed: bool,
    pub is_active_current_epoch: bool,
    pub is_active_previous_epoch: bool,
    pub previous_epoch_participation: ParticipationFlags,
}

impl ValidatorInfo {
    #[inline]
    pub fn is_unslashed_participating_index(&self, flag_index: usize) -> Result<bool, Error> {
        Ok(self.is_active_previous_epoch
            && !self.is_slashed
            && self
                .previous_epoch_participation
                .has_flag(flag_index)
                .map_err(|_| Error::InvalidFlagIndex(flag_index))?)
    }
}

pub fn process_epoch_single_pass<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch()?;
    let is_in_inactivity_leak = state.is_in_inactivity_leak(previous_epoch, spec);

    let state_ctxt = &StateContext {
        previous_epoch,
        current_epoch,
        next_epoch,
        is_in_inactivity_leak,
    };

    let (
        validators,
        balances,
        previous_epoch_participation,
        current_epoch_participation,
        inactivity_scores,
        progressive_balances,
        epoch_cache,
    ) = state.mutable_validator_fields()?;

    let num_validators = validators.len();

    let mut validators_iter = validators.iter_cow();
    let mut balances_iter = balances.iter_cow();
    let mut inactivity_scores_iter = inactivity_scores.iter_cow();

    for (index, &previous_epoch_participation, &current_epoch_participation) in izip!(
        0..num_validators,
        previous_epoch_participation.iter(),
        current_epoch_participation.iter(),
    ) {
        // FIXME(sproul): unwrap
        let (_, validator_cow) = validators_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;
        let (_, balance_cow) = balances_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;
        let (_, inactivity_score_cow) = inactivity_scores_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;

        let validator = validator_cow.to_mut();
        let balance = balance_cow.to_mut();
        let inactivity_score = inactivity_score_cow.to_mut();

        let base_reward = epoch_cache.get_base_reward(index)?;

        let is_active_current_epoch = validator.is_active_at(current_epoch);
        let is_active_previous_epoch = validator.is_active_at(previous_epoch);
        let is_eligible = is_active_previous_epoch
            || (validator.slashed()
                && previous_epoch + Epoch::new(1) < validator.withdrawable_epoch());

        let validator_info = &ValidatorInfo {
            effective_balance: validator.effective_balance(),
            base_reward,
            is_eligible,
            is_slashed: validator.slashed(),
            is_active_current_epoch,
            is_active_previous_epoch,
            previous_epoch_participation,
        };

        if current_epoch != E::genesis_epoch() {
            // `process_inactivity_updates`
            process_single_inactivity_update(inactivity_score, validator_info, state_ctxt, spec)?;

            // `process_rewards_and_penalties`
            process_single_reward_and_penalty()?;
        }
    }

    Ok(())
}

fn process_single_inactivity_update(
    inactivity_score: &mut u64,
    validator_info: &ValidatorInfo,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if !validator_info.is_eligible {
        return Ok(());
    }

    // Increase inactivity score of inactive validators
    if validator_info.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
        // Avoid mutating when the inactivity score is 0 and can't go any lower -- the common
        // case.
        if *inactivity_score == 0 {
            return Ok(());
        }
        inactivity_score.safe_sub_assign(1)?;
    } else {
        inactivity_score.safe_add_assign(spec.inactivity_score_bias)?;
    }

    // Decrease the score of all validators for forgiveness when not during a leak
    if !state_ctxt.is_in_inactivity_leak {
        inactivity_score
            .safe_sub_assign(min(spec.inactivity_score_recovery_rate, *inactivity_score))?;
    }

    Ok(())
}

fn process_single_reward_and_penalty(
    inactivity_score: &mut u64,
    validator_info: &ValidatorInfo,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
}

fn get_flag_index_delta<T: EthSpec>(
    deltas: &Delta,
    flag_index: usize,
    epoch_cache: &EpochCache,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let weight = get_flag_weight(flag_index)?;
    let unslashed_participating_balance =
        participation_cache.previous_epoch_flag_attesting_balance(flag_index)?;
    let unslashed_participating_increments =
        unslashed_participating_balance.safe_div(spec.effective_balance_increment)?;
    let active_increments = total_active_balance.safe_div(spec.effective_balance_increment)?;
    let previous_epoch = state.previous_epoch();

    for &index in participation_cache.eligible_validator_indices() {
        let validator = participation_cache.get_validator(index)?;
        let base_reward = validator.base_reward;

        let mut delta = Delta::default();

        if validator.is_unslashed_participating_index(flag_index)? {
            if !state.is_in_inactivity_leak(previous_epoch, spec) {
                let reward_numerator = base_reward
                    .safe_mul(weight)?
                    .safe_mul(unslashed_participating_increments)?;
                delta.reward(
                    reward_numerator.safe_div(active_increments.safe_mul(WEIGHT_DENOMINATOR)?)?,
                )?;
            }
        } else if flag_index != TIMELY_HEAD_FLAG_INDEX {
            delta.penalize(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?)?;
        }
        deltas
            .get_mut(index)
            .ok_or(Error::DeltaOutOfBounds(index))?
            .combine(delta)?;
    }
    Ok(())
}

/// Get the weight for a `flag_index` from the constant list of all weights.
pub fn get_flag_weight(flag_index: usize) -> Result<u64, Error> {
    PARTICIPATION_FLAG_WEIGHTS
        .get(flag_index)
        .copied()
        .ok_or(Error::InvalidFlagIndex(flag_index))
}
