use super::errors::EpochProcessingError;
use safe_arith::SafeArith;
use tree_hash::TreeHash;
use typenum::Unsigned;
use types::core::EthSpec;
use types::state::BeaconState;

pub fn process_historical_roots_update<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    let next_epoch = state.next_epoch()?;
    if next_epoch
        .as_u64()
        .safe_rem(E::SlotsPerHistoricalRoot::to_u64().safe_div(E::slots_per_epoch())?)?
        == 0
    {
        let historical_batch = state.historical_batch()?;
        state
            .historical_roots_mut()
            .push(historical_batch.tree_hash_root())?;
    }
    Ok(())
}
