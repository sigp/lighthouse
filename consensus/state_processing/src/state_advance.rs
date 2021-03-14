use crate::*;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    BadTargetSlot { target_slot: Slot, state_slot: Slot },
    PerSlotProcessing(per_slot_processing::Error),
    StateRootNotProvided,
}

pub fn complete_state_advance<T: EthSpec>(
    state: &mut BeaconState<T>,
    mut state_root: Option<Hash256>,
    target_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), Error> {
    check_target_slot(state.slot, target_slot)?;

    while state.slot < target_slot {
        // Use the initial state root on the first iteration of the loop, then use `None`  for any
        // future iterations.
        let state_root_opt = state_root.take();

        per_slot_processing(state, state_root_opt, spec).map_err(Error::PerSlotProcessing)?;
    }

    Ok(())
}

pub fn partial_state_advance<T: EthSpec>(
    state: &mut BeaconState<T>,
    state_root: Option<Hash256>,
    target_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), Error> {
    check_target_slot(state.slot, target_slot)?;

    let mut initial_state_root = Some(if state.slot > state.latest_block_header.slot {
        state_root.unwrap_or(Hash256::zero())
    } else {
        state_root.ok_or_else(|| Error::StateRootNotProvided)?
    });

    while state.slot < target_slot {
        // Use the initial state root on the first iteration of the loop, then use `[0; 32]` for any
        // later iterations.
        //
        // Failing to provide the correct state root on the initial iteration may result in
        // corrupting the `state.block_roots` array since the latest block header may not be updated
        // with the correct state root.
        let state_root = initial_state_root.take().unwrap_or(Hash256::zero());

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
