use super::ParticipationCache;
use crate::EpochProcessingError;
use safe_arith::SafeArith;
use std::cmp::min;
use std::cmp::Ordering;
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
    let is_in_inactivity_leak = state.is_in_inactivity_leak(spec);

    let unslashed_indices = participation_cache
        .get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, state.previous_epoch())?;

    let mut eligible_validators_iter = participation_cache
        .eligible_validator_indices()
        .iter()
        .peekable();

    // FIXME(sproul): this is a really ugly hack
    let mut is_eligible = |index: usize| -> bool {
        while let Some(&eligible_index) = eligible_validators_iter.peek() {
            match eligible_index.cmp(&index) {
                // Should visit every
                Ordering::Less => {
                    unreachable!("should have already visited {}", eligible_index)
                }
                Ordering::Equal => {
                    eligible_validators_iter.next();
                    return true;
                }
                Ordering::Greater => {
                    return false;
                }
            }
        }
        false
    };

    let mut inactivity_scores = state.inactivity_scores_mut()?.iter_cow();

    while let Some((index, inactivity_score)) = inactivity_scores.next_cow() {
        if !is_eligible(index) {
            continue;
        }

        let inactivity_score = inactivity_score.to_mut();

        // Increase inactivity score of inactive validators
        if unslashed_indices.contains(index)? {
            inactivity_score.safe_sub_assign(min(1, *inactivity_score))?;
        } else {
            inactivity_score.safe_add_assign(spec.inactivity_score_bias)?;
        }

        // Decrease the score of all validators for forgiveness when not during a leak
        if !is_in_inactivity_leak {
            inactivity_score
                .safe_sub_assign(min(spec.inactivity_score_recovery_rate, *inactivity_score))?;
        }
    }
    Ok(())
}
