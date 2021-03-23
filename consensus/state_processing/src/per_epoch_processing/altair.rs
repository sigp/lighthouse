use crate::per_epoch_processing::{EpochProcessingSummary, Error};
use types::{BeaconState, ChainSpec, EthSpec};

// FIXME(altair): implement
pub fn process_epoch<T: EthSpec>(
    _state: &mut BeaconState<T>,
    _spec: &ChainSpec,
) -> Result<EpochProcessingSummary, Error> {
    unimplemented!()
}
