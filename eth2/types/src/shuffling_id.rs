use crate::{BeaconState, BeaconStateError, Epoch, EthSpec, Hash256};

/// An identifier for some set of "shuffling" (A.K.A, a `crate::beacon_state::CommitteeCache`).
///
/// A `ShufflingId` can be used to uniquely identify the committees for the current epoch of a
/// `BeaconState` without needing to compute the seed or do any shuffling.
///
/// For example, if there is a `HashMap<ShufflingId, CommitteeCache>`, then for any `BeaconState`
/// you can do a cheap lookup to see if the shuffling for that state exists in the cache.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct ShufflingId(Epoch, Hash256);

impl ShufflingId {
    /// Returns the shuffling ID for the current epoch of the given state.
    pub fn of_current_epoch<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, BeaconStateError> {
        let previous_epoch_boundary_state_root =
            *state.get_state_root(state.previous_epoch().start_slot(T::slots_per_epoch()))?;

        Ok(Self(
            state.current_epoch(),
            previous_epoch_boundary_state_root,
        ))
    }
}
