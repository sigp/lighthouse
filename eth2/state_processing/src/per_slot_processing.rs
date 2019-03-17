use crate::*;
use types::{BeaconState, BeaconStateError, ChainSpec, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconStateError(BeaconStateError),
    EpochProcessingError(EpochProcessingError),
}

/// Advances a state forward by one slot, performing per-epoch processing if required.
///
/// Spec v0.5.0
pub fn per_slot_processing(
    state: &mut BeaconState,
    previous_block_root: Hash256,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if (state.slot + 1) % spec.slots_per_epoch == 0 {
        per_epoch_processing(state, spec)?;
        state.advance_caches();
    }

    state.slot += 1;

    Ok(())
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<EpochProcessingError> for Error {
    fn from(e: EpochProcessingError) -> Error {
        Error::EpochProcessingError(e)
    }
}
