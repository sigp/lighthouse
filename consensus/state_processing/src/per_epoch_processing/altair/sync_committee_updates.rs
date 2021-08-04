use crate::EpochProcessingError;
use safe_arith::SafeArith;
use std::sync::Arc;
use types::beacon_state::BeaconState;
use types::chain_spec::ChainSpec;
use types::eth_spec::EthSpec;

pub fn process_sync_committee_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let next_epoch = state.next_epoch()?;
    if next_epoch.safe_rem(spec.epochs_per_sync_committee_period)? == 0 {
        *state.current_sync_committee_mut()? = state.next_sync_committee()?.clone();

        *state.next_sync_committee_mut()? = Arc::new(state.get_next_sync_committee(spec)?);
    }
    Ok(())
}
