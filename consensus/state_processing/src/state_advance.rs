//! This module contains functions for advancing a `BeaconState` forward some number of slots
//! without blocks (i.e., skip slots).
//!
//! These functions are not in the specification, however they're defined here to reduce code
//! duplication and protect against some easy-to-make mistakes when performing state advances.

use crate::*;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    BadTargetSlot { target_slot: Slot, state_slot: Slot },
    PerSlotProcessing(per_slot_processing::Error),
    StateRootNotProvided,
}

/// Advances the `state` to the given `target_slot`, assuming that there were no blocks between
/// these slots.
///
/// ## Errors
///
/// - If `state.slot > target_slot`, an error will be returned.
///
/// ## Notes
///
/// This state advance method is "complete"; it outputs a perfectly valid `BeaconState` and doesn't
/// do anything hacky like the "partial" method (see `partial_state_advance`).
pub fn complete_state_advance<T: EthSpec>(
    state: &mut BeaconState<T>,
    mut state_root_opt: Option<Hash256>,
    target_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), Error> {
    check_target_slot(state.slot(), target_slot)?;

    while state.slot() < target_slot {
        // Use the initial state root on the first iteration of the loop, then use `None`  for any
        // future iterations.
        let state_root_opt = state_root_opt.take();

        per_slot_processing(state, state_root_opt, spec).map_err(Error::PerSlotProcessing)?;
    }

    Ok(())
}

/// Advances the `state` to the given `target_slot`, assuming that there were no blocks between
/// these slots.
///
/// This is a "partial" state advance which outputs an **invalid** `BeaconState`. The state is
/// invalid because the intermediate state roots are not computed. Avoiding computing state roots
/// saves *a lot* of compute time and can be a useful optimization when a state only needs to be
/// advanced to obtain proposer/attester shuffling as they are indifferent to state roots.
///
/// For clarity, **be careful with this function as it produces invalid states**.
///
/// ## Errors
///
/// - If `state.slot > target_slot`, an error will be returned.
/// - If `state_root_opt.is_none()` but the latest block header requires a state root.
pub fn partial_state_advance<T: EthSpec>(
    state: &mut BeaconState<T>,
    state_root_opt: Option<Hash256>,
    target_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), Error> {
    check_target_slot(state.slot(), target_slot)?;

    // The only time that a state root is mandatory is if a block has been applied to the state
    // without it yet being advanced another slot.
    //
    // Failing to provide a state root in this scenario would result in corrupting the
    // `state.block_roots` array, since the `state.latest_block_header` would contain an invalid
    // (all-zeros) state root.
    let mut initial_state_root = Some(if state.slot() > state.latest_block_header().slot {
        state_root_opt.unwrap_or_else(Hash256::zero)
    } else {
        state_root_opt.ok_or(Error::StateRootNotProvided)?
    });

    while state.slot() < target_slot {
        // Use the initial state root on the first iteration of the loop, then use `[0; 32]` for any
        // later iterations.
        //
        // Failing to provide the correct state root on the initial iteration may result in
        // corrupting the `state.block_roots` array since the latest block header may not be updated
        // with the correct state root.
        let state_root = initial_state_root.take().unwrap_or_else(Hash256::zero);

        per_slot_processing(state, Some(state_root), spec).map_err(Error::PerSlotProcessing)?;
    }

    Ok(())
}

fn check_target_slot(state_slot: Slot, target_slot: Slot) -> Result<(), Error> {
    if state_slot > target_slot {
        Err(Error::BadTargetSlot {
            target_slot,
            state_slot,
        })
    } else {
        Ok(())
    }
}
