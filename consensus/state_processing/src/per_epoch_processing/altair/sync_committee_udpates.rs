use crate::EpochProcessingError;
use core::result::Result;
use core::result::Result::Ok;
use safe_arith::SafeArith;
use types::beacon_state::BeaconState;
use types::chain_spec::ChainSpec;
use types::eth_spec::EthSpec;

pub fn process_sync_committee_udpates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let next_epoch = state.next_epoch()?;
    if next_epoch.safe_rem(spec.epochs_per_sync_committee_period)? == 0 {
        state.as_altair_mut()?.current_sync_committee =
            state.as_altair()?.next_sync_committee.clone();
        state.as_altair_mut()?.next_sync_committee = state.get_sync_committee(
            next_epoch.safe_add(spec.epochs_per_sync_committee_period)?,
            spec,
        )?;
    }
    Ok(())
}
