use super::ParticipationCache;
use crate::EpochProcessingError;
use core::result::Result;
use core::result::Result::Ok;
use safe_arith::SafeArith;
use std::cmp::min;
use types::beacon_state::BeaconState;
use types::chain_spec::ChainSpec;
use types::consts::altair::TIMELY_TARGET_FLAG_INDEX;
use types::eth_spec::EthSpec;

pub fn process_inactivity_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    participation_cache: &ParticipationCache,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    // Score updates based on previous epoch participation, skip genesis epoch
    if state.current_epoch() == T::genesis_epoch() {
        return Ok(());
    }

    let unslashed_indices = participation_cache
        .get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, state.previous_epoch())?;

    for &index in participation_cache.eligible_validator_indices() {
        // Increase inactivity score of inactive validators
        if unslashed_indices.contains(index)? {
            let inactivity_score = state.get_inactivity_score_mut(index)?;
            inactivity_score.safe_sub_assign(min(1, *inactivity_score))?;
        } else {
            state
                .get_inactivity_score_mut(index)?
                .safe_add_assign(spec.inactivity_score_bias)?;
        }
        // Decrease the score of all validators for forgiveness when not during a leak
        if !state.is_in_inactivity_leak(spec) {
            let inactivity_score = state.get_inactivity_score_mut(index)?;
            inactivity_score
                .safe_sub_assign(min(spec.inactivity_score_recovery_rate, *inactivity_score))?;
        }
    }
    Ok(())
}
