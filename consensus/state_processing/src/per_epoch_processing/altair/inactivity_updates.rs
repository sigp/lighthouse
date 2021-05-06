use crate::EpochProcessingError;
use core::result::Result;
use core::result::Result::Ok;
use safe_arith::SafeArith;
use types::beacon_state::BeaconState;
use types::chain_spec::ChainSpec;
use types::consts::altair::{INACTIVITY_SCORE_BIAS, TIMELY_TARGET_FLAG_INDEX};
use types::eth_spec::EthSpec;

// FIXME(altair): there's no EF test for this one (yet)
pub fn process_inactivity_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    for index in state.get_eligible_validator_indices()? {
        let unslashed_indices = state.get_unslashed_participating_indices(
            TIMELY_TARGET_FLAG_INDEX,
            state.previous_epoch(),
            spec,
        )?;
        if unslashed_indices.contains(&index) {
            let inactivity_score = state.get_inactivity_score_mut(index)?;
            if *inactivity_score > 0 {
                inactivity_score.safe_sub_assign(1)?;
            }
        } else if state.is_in_inactivity_leak(spec) {
            state
                .get_inactivity_score_mut(index)?
                .safe_add_assign(INACTIVITY_SCORE_BIAS)?;
        }
    }
    Ok(())
}
