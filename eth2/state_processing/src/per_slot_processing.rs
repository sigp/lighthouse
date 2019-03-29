use crate::*;
use ssz::TreeHash;
use types::*;

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
    latest_block_header: &BeaconBlockHeader,
    spec: &ChainSpec,
) -> Result<(), Error> {
    cache_state(state, latest_block_header, spec)?;

    if (state.slot + 1) % spec.slots_per_epoch == 0 {
        per_epoch_processing(state, spec)?;
    }

    state.slot += 1;

    Ok(())
}

fn cache_state(
    state: &mut BeaconState,
    latest_block_header: &BeaconBlockHeader,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let previous_slot_state_root = Hash256::from_slice(&state.hash_tree_root()[..]);

    // Note: increment the state slot here to allow use of our `state_root` and `block_root`
    // getter/setter functions.
    //
    // This is a bit hacky, however it gets the job safely without lots of code.
    let previous_slot = state.slot;
    state.slot += 1;

    // Store the previous slot's post-state transition root.
    if state.latest_block_header.state_root == spec.zero_hash {
        state.latest_block_header.state_root = previous_slot_state_root
    }

    let latest_block_root = Hash256::from_slice(&latest_block_header.hash_tree_root()[..]);
    state.set_block_root(previous_slot, latest_block_root, spec)?;

    // Set the state slot back to what it should be.
    state.slot -= 1;

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
