use crate::EpochProcessingError;
use safe_arith::SafeArith;
use types::historical_summary::HistoricalSummary;
use types::{BeaconState, EthSpec};

pub fn process_historical_summaries_update<T: EthSpec>(
    state: &mut BeaconState<T>,
) -> Result<(), EpochProcessingError> {
    // Set historical block root accumulator.
    let next_epoch = state.next_epoch()?;
    if next_epoch
        .as_u64()
        .safe_rem((T::slots_per_historical_root() as u64).safe_div(T::slots_per_epoch())?)?
        == 0
    {
        let summary = HistoricalSummary::new(state);
        return state
            .historical_summaries_mut()?
            .push(summary)
            .map_err(Into::into);
    }
    Ok(())
}
