use crate::*;
use types::{BeaconState, BeaconStateError, ChainSpec, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconStateError(BeaconStateError),
    EpochProcessingError(EpochProcessingError),
}

/// Advances a state forward by one slot, performing per-epoch processing if required.
///
/// Spec v0.4.0
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

    update_block_roots(state, previous_block_root, spec);

    Ok(())
}

/// Updates the state's block roots as per-slot processing is performed.
///
/// Spec v0.4.0
pub fn update_block_roots(state: &mut BeaconState, previous_block_root: Hash256, spec: &ChainSpec) {
    state.latest_block_roots[(state.slot.as_usize() - 1) % spec.latest_block_roots_length] =
        previous_block_root;

    if state.slot.as_usize() % spec.latest_block_roots_length == 0 {
        let root = merkle_root(&state.latest_block_roots[..]);
        state.batched_block_roots.push(root);
    }
}

fn merkle_root(_input: &[Hash256]) -> Hash256 {
    // TODO: implement correctly.
    Hash256::zero()
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
