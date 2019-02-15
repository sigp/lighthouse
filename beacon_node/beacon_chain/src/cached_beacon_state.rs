use types::{beacon_state::BeaconStateError, BeaconState, ChainSpec, Epoch, Slot};

pub const CACHED_EPOCHS: usize = 3; // previous, current, next.

pub type CrosslinkCommittees = Vec<(Vec<usize>, u64)>;

pub struct CachedBeaconState<'a> {
    state: BeaconState,
    crosslinks: Vec<Vec<CrosslinkCommittees>>,
    spec: &'a ChainSpec,
}

impl<'a> CachedBeaconState<'a> {
    pub fn from_beacon_state(
        state: BeaconState,
        spec: &'a ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let current_epoch = state.current_epoch(spec);
        let previous_epoch = if current_epoch == spec.genesis_epoch {
            current_epoch
        } else {
            current_epoch.saturating_sub(1_u64)
        };
        let next_epoch = state.next_epoch(spec);

        let mut crosslinks: Vec<Vec<CrosslinkCommittees>> = Vec::with_capacity(3);
        crosslinks.push(committees_for_all_slots(&state, previous_epoch, spec)?);
        crosslinks.push(committees_for_all_slots(&state, current_epoch, spec)?);
        crosslinks.push(committees_for_all_slots(&state, next_epoch, spec)?);

        Ok(Self {
            state,
            crosslinks,
            spec,
        })
    }
}

fn committees_for_all_slots(
    state: &BeaconState,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<Vec<CrosslinkCommittees>, BeaconStateError> {
    let mut crosslinks: Vec<CrosslinkCommittees> = Vec::with_capacity(spec.epoch_length as usize);
    for slot in epoch.slot_iter(spec.epoch_length) {
        crosslinks.push(state.get_crosslink_committees_at_slot(slot, false, spec)?)
    }
    Ok(crosslinks)
}
