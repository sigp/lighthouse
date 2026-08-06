use super::errors::EpochProcessingError;
use safe_arith::SafeArith;
use tree_hash::TreeHash;
use types::Spec;
use types::state::BeaconState;

pub fn process_historical_roots_update(
    state: &mut BeaconState,
) -> Result<(), EpochProcessingError> {
    let next_epoch = state.next_epoch()?;
    if next_epoch
        .as_u64()
        .safe_rem((Spec::slots_per_historical_root()).safe_div(Spec::slots_per_epoch())?)?
        == 0
    {
        let historical_batch = state.historical_batch()?;
        state
            .historical_roots_mut()
            .push(historical_batch.tree_hash_root())?;
    }
    Ok(())
}
