use crate::EpochProcessingError;
use safe_arith::SafeArith;
use types::historical_summary::HistoricalSummary;
use types::{BeaconState, EthSpec};

pub fn process_historical_summaries_update<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    // Set historical block root accumulator.
    let next_epoch = state.next_epoch()?;
    if next_epoch
        .as_u64()
        .safe_rem((E::slots_per_historical_root() as u64).safe_div(E::slots_per_epoch())?)?
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
