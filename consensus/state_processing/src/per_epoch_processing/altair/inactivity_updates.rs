use super::ParticipationCache;
use crate::EpochProcessingError;
use safe_arith::SafeArith;
use std::cmp::min;
use types::beacon_state::BeaconState;
use types::chain_spec::ChainSpec;
use types::consts::altair::TIMELY_TARGET_FLAG_INDEX;
use types::eth_spec::EthSpec;

pub fn process_inactivity_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    participation_cache: &mut ParticipationCache,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let previous_epoch = state.previous_epoch();
    // Score updates based on previous epoch participation, skip genesis epoch
    if state.current_epoch() == T::genesis_epoch() {
        return Ok(());
    }

    // Fast path: inactivity scores have already been pre-computed.
    if let Some(inactivity_score_updates) = participation_cache.inactivity_score_updates.take() {
        // We need to flush the existing inactivity scores in case tree hashing hasn't happened in
        // a long time (e.g. during state reconstruction).
        // FIXME(sproul): re-think this
        state.inactivity_scores_mut()?.apply_updates()?;
        state
            .inactivity_scores_mut()?
            .bulk_update(inactivity_score_updates)?;
        return Ok(());
    }

    let is_in_inactivity_leak = state.is_in_inactivity_leak(previous_epoch, spec);

    let mut inactivity_scores = state.inactivity_scores_mut()?.iter_cow();

    while let Some((index, inactivity_score)) = inactivity_scores.next_cow() {
        let validator = match participation_cache.get_validator(index) {
            Ok(val) if val.is_eligible => val,
            _ => continue,
        };

        let inactivity_score_mut;

        // Increase inactivity score of inactive validators
        if validator.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
            // Avoid mutating when the inactivity score is 0 and can't go any lower -- the common
            // case.
            if *inactivity_score == 0 {
                continue;
            }
            inactivity_score_mut = inactivity_score.to_mut();
            inactivity_score_mut.safe_sub_assign(1)?;
        } else {
            inactivity_score_mut = inactivity_score.to_mut();
            inactivity_score_mut.safe_add_assign(spec.inactivity_score_bias)?;
        }

        // Decrease the score of all validators for forgiveness when not during a leak
        if !is_in_inactivity_leak {
            inactivity_score_mut.safe_sub_assign(min(
                spec.inactivity_score_recovery_rate,
                *inactivity_score_mut,
            ))?;
        }
    }
    Ok(())
}
