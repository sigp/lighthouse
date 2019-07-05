use crate::*;
use types::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconStateError(BeaconStateError),
    EpochProcessingError(EpochProcessingError),
}

/// Advances a state forward by one slot, performing per-epoch processing if required.
///
/// Spec v0.8.0
pub fn per_slot_processing<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    cache_state(state)?;

    if state.slot > spec.genesis_slot && (state.slot + 1) % T::slots_per_epoch() == 0 {
        per_epoch_processing(state, spec)?;
    }

    state.slot += 1;

    Ok(())
}

fn cache_state<T: EthSpec>(state: &mut BeaconState<T>) -> Result<(), Error> {
    let previous_state_root = state.update_tree_hash_cache()?;

    // Note: increment the state slot here to allow use of our `state_root` and `block_root`
    // getter/setter functions.
    //
    // This is a bit hacky, however it gets the job safely without lots of code.
    let previous_slot = state.slot;
    state.slot += 1;

    // Store the previous slot's post state transition root.
    state.set_state_root(previous_slot, previous_state_root)?;

    // Cache latest block header state root
    if state.latest_block_header.state_root == Hash256::zero() {
        state.latest_block_header.state_root = previous_state_root;
    }

    // Cache block root
    let latest_block_root = state.latest_block_header.canonical_root();
    state.set_block_root(previous_slot, latest_block_root)?;

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
