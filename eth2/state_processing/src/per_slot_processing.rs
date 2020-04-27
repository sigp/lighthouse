use crate::*;
use types::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconStateError(BeaconStateError),
    EpochProcessingError(EpochProcessingError),
}

/// Advances a state forward by one slot, performing per-epoch processing if required.
///
/// If the root of the supplied `state` is known, then it can be passed as `state_root`. If
/// `state_root` is `None`, the root of `state` will be computed using a cached tree hash.
/// Providing the `state_root` makes this function several orders of magniude faster.
///
/// Spec v0.11.1
pub fn per_slot_processing<T: EthSpec>(
    state: &mut BeaconState<T>,
    state_root: Option<Hash256>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    cache_state(state, state_root)?;

    if state.slot > spec.genesis_slot && (state.slot + 1) % T::slots_per_epoch() == 0 {
        per_epoch_processing(state, spec)?;
    }

    state.slot += 1;

    Ok(())
}

fn cache_state<T: EthSpec>(
    state: &mut BeaconState<T>,
    state_root: Option<Hash256>,
) -> Result<(), Error> {
    let previous_state_root = if let Some(root) = state_root {
        root
    } else {
        state.update_tree_hash_cache()?
    };

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
