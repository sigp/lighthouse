use crate::EpochProcessingError;
use safe_arith::SafeArith;
use types::state::HistoricalSummary;
use types::{BeaconState, Spec};

pub fn process_historical_summaries_update(
    state: &mut BeaconState,
) -> Result<(), EpochProcessingError> {
    // Set historical block root accumulator.
    let next_epoch = state.next_epoch()?;
    if next_epoch
        .as_u64()
        .safe_rem((Spec::slots_per_historical_root()).safe_div(Spec::slots_per_epoch())?)?
        == 0
    {
        // We need to flush any pending mutations before hashing.
        state.block_roots_mut().apply_updates()?;
        state.state_roots_mut().apply_updates()?;
        let summary = HistoricalSummary::new(state);
        return state
            .historical_summaries_mut()?
            .push(summary)
            .map_err(Into::into);
    }
    Ok(())
}
