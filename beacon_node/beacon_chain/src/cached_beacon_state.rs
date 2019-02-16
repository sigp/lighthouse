use log::debug;
use std::collections::HashMap;
use types::{beacon_state::BeaconStateError, BeaconState, ChainSpec, Epoch, Slot};

pub const CACHE_PREVIOUS: bool = false;
pub const CACHE_CURRENT: bool = true;
pub const CACHE_NEXT: bool = false;

pub type CrosslinkCommittees = Vec<(Vec<usize>, u64)>;
pub type Shard = u64;
pub type CommitteeIndex = u64;
pub type AttestationDuty = (Slot, Shard, CommitteeIndex);
pub type AttestationDutyMap = HashMap<u64, AttestationDuty>;

// TODO: CachedBeaconState is presently duplicating `BeaconState` and `ChainSpec`. This is a
// massive memory waste, switch them to references.

pub struct CachedBeaconState {
    pub state: BeaconState,
    committees: Vec<Vec<CrosslinkCommittees>>,
    attestation_duties: Vec<AttestationDutyMap>,
    next_epoch: Epoch,
    current_epoch: Epoch,
    previous_epoch: Epoch,
    spec: ChainSpec,
}

impl CachedBeaconState {
    pub fn from_beacon_state(
        state: BeaconState,
        spec: ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let current_epoch = state.current_epoch(&spec);
        let previous_epoch = if current_epoch == spec.genesis_epoch {
            current_epoch
        } else {
            current_epoch.saturating_sub(1_u64)
        };
        let next_epoch = state.next_epoch(&spec);

        let mut committees: Vec<Vec<CrosslinkCommittees>> = Vec::with_capacity(3);
        let mut attestation_duties: Vec<AttestationDutyMap> = Vec::with_capacity(3);

        if CACHE_PREVIOUS {
            debug!("CachedBeaconState::from_beacon_state: building previous epoch cache.");
            let cache = build_epoch_cache(&state, previous_epoch, &spec)?;
            committees.push(cache.committees);
            attestation_duties.push(cache.attestation_duty_map);
        } else {
            committees.push(vec![]);
            attestation_duties.push(HashMap::new());
        }
        if CACHE_CURRENT {
            debug!("CachedBeaconState::from_beacon_state: building current epoch cache.");
            let cache = build_epoch_cache(&state, current_epoch, &spec)?;
            committees.push(cache.committees);
            attestation_duties.push(cache.attestation_duty_map);
        } else {
            committees.push(vec![]);
            attestation_duties.push(HashMap::new());
        }
        if CACHE_NEXT {
            debug!("CachedBeaconState::from_beacon_state: building next epoch cache.");
            let cache = build_epoch_cache(&state, next_epoch, &spec)?;
            committees.push(cache.committees);
            attestation_duties.push(cache.attestation_duty_map);
        } else {
            committees.push(vec![]);
            attestation_duties.push(HashMap::new());
        }

        Ok(Self {
            state,
            committees,
            attestation_duties,
            next_epoch,
            current_epoch,
            previous_epoch,
            spec,
        })
    }

    fn slot_to_cache_index(&self, slot: Slot) -> Option<usize> {
        match slot.epoch(self.spec.epoch_length) {
            epoch if (epoch == self.previous_epoch) & CACHE_PREVIOUS => Some(0),
            epoch if (epoch == self.current_epoch) & CACHE_CURRENT => Some(1),
            epoch if (epoch == self.next_epoch) & CACHE_NEXT => Some(2),
            _ => None,
        }
    }

    /// Returns the `slot`, `shard` and `committee_index` for which a validator must produce an
    /// attestation.
    ///
    /// Cached method.
    ///
    /// Spec v0.2.0
    pub fn attestation_slot_and_shard_for_validator(
        &self,
        validator_index: usize,
        _spec: &ChainSpec,
    ) -> Result<Option<(Slot, u64, u64)>, BeaconStateError> {
        // Get the result for this epoch.
        let cache_index = self
            .slot_to_cache_index(self.state.slot)
            .expect("Current epoch should always have a cache index.");

        let duties = self.attestation_duties[cache_index]
            .get(&(validator_index as u64))
            .and_then(|tuple| Some(*tuple));

        Ok(duties)
    }
}

struct EpochCacheResult {
    committees: Vec<CrosslinkCommittees>,
    attestation_duty_map: AttestationDutyMap,
}

fn build_epoch_cache(
    state: &BeaconState,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<EpochCacheResult, BeaconStateError> {
    let mut epoch_committees: Vec<CrosslinkCommittees> =
        Vec::with_capacity(spec.epoch_length as usize);
    let mut attestation_duty_map: AttestationDutyMap = HashMap::new();

    for slot in epoch.slot_iter(spec.epoch_length) {
        let slot_committees = state.get_crosslink_committees_at_slot(slot, false, spec)?;

        for (committee, shard) in slot_committees {
            for (committee_index, validator_index) in committee.iter().enumerate() {
                attestation_duty_map.insert(
                    *validator_index as u64,
                    (slot, shard, committee_index as u64),
                );
            }
        }

        epoch_committees.push(state.get_crosslink_committees_at_slot(slot, false, spec)?)
    }

    Ok(EpochCacheResult {
        committees: epoch_committees,
        attestation_duty_map,
    })
}
