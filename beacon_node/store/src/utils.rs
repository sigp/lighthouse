use crate::StoreError as Error;
use types::{BeaconState, EthSpec, Hash256, Slot};

pub fn get_state_root_from_state<E: EthSpec>(state: &BeaconState<E>) -> Result<Hash256, Error> {
    state.update_tree_hash_cache()?;
    Ok(state.tree_hash_root())
}

pub fn get_state_root_from_slot<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
) -> Result<Hash256, Error> {
    if slot > state.slot() {
        return Err(Error::SlotOutOfRange {
            requested: slot,
            head: state.slot(),
        });
    }

    let state_root = if slot == state.slot() {
        get_state_root_from_state(state)?
    } else {
        state.get_state_root(slot)?
    };

 