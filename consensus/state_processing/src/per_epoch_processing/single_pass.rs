use crate::per_epoch_processing::{
    process_registry_updates, process_slashings, EpochProcessingSummary, Error,
};
use itertools::izip;
use std::cmp::{max, min};
use types::{
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
    BeaconState, ChainSpec, Epoch, EthSpec, ParticipationFlags,
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

    // FIXME(sproul): use iter_cow
    for (
        index,
        validator,
        balance,
        &previous_epoch_participation,
        current_epoch_participation,
        inactivity_score,
    ) in izip!(
        0..num_validators,
        validators.iter_mut(),
        balances.iter(),
        previous_epoch_participation.iter(),
        current_epoch_participation.iter(),
        inactivity_scores.iter_mut()
    ) {
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

        // `process_inactivity_updates`
        if current_epoch != E::genesis_epoch() {
            process_single_inactivity_update(inactivity_score, validator_info, state_ctxt, spec)?;
        }
    }
}

pub fn process_single_inactivity_update(
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
            return;
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
