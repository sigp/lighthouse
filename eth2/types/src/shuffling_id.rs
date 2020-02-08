use crate::{BeaconState, BeaconStateError, Epoch, EthSpec, Hash256};
use tree_hash::TreeHash;

/// An identifier for some set of "shuffling" (A.K.A, a `crate::beacon_state::CommitteeCache`).
///
/// A `ShufflingId` can be used to uniquely identify the committees for the current epoch of a
/// `BeaconState` without needing to compute the seed or do any shuffling.
///
/// For example, if there is a `HashMap<ShufflingId, CommitteeCache>`, then for any `BeaconState`
/// you can do a cheap lookup to see if the shuffling for that state exists in the cache.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct ShufflingId {
    epoch: Epoch,
    epoch_boundary_block_root: Hash256,
}

/*
impl ShufflingId {


    /// Returns the shuffling ID for the current epoch of the given state.
    pub fn of_current_epoch<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, BeaconStateError> {
        let epoch = state.current_epoch();
        let epoch_boundary_slot = epoch.start_slot(T::slots_per_epoch());

        if state.slot == epoch_boundary_slot

        let epoch_boundary_block_root =
            state.get_state_root(epoch.start_slot(T::slots_per_epoch()))
            .cloned()
            .unwrap_or_else(|_| Hash256::from_slice(&state.latest_block_header.tree_hash_root()));

        Ok(Self {
            epoch, epoch_boundary_block_root
        })
    }
}
*/
