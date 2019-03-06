use std::collections::HashSet;
use types::*;

#[derive(Default)]
pub struct Attesters {
    pub indices: HashSet<usize>,
    pub balance: u64,
}

impl Attesters {
    fn add(&mut self, additional_indices: &[usize], additional_balance: u64) {
        self.indices.reserve(additional_indices.len());
        for i in additional_indices {
            self.indices.insert(*i);
        }
        self.balance.saturating_add(additional_balance);
    }
}

pub struct GroupedAttesters {
    pub current_epoch: Attesters,
    pub current_epoch_boundary: Attesters,
    pub previous_epoch: Attesters,
    pub previous_epoch_boundary: Attesters,
    pub previous_epoch_head: Attesters,
}

impl GroupedAttesters {
    pub fn new(state: &BeaconState, spec: &ChainSpec) -> Result<Self, BeaconStateError> {
        let mut current_epoch = Attesters::default();
        let mut current_epoch_boundary = Attesters::default();
        let mut previous_epoch = Attesters::default();
        let mut previous_epoch_boundary = Attesters::default();
        let mut previous_epoch_head = Attesters::default();

        for a in &state.latest_attestations {
            let attesting_indices =
                state.get_attestation_participants(&a.data, &a.aggregation_bitfield, spec)?;
            let attesting_balance = state.get_total_balance(&attesting_indices, spec);

            if is_from_epoch(a, state.current_epoch(spec), spec) {
                current_epoch.add(&attesting_indices, attesting_balance);

                if has_common_epoch_boundary_root(a, state, state.current_epoch(spec), spec)? {
                    current_epoch_boundary.add(&attesting_indices, attesting_balance);
                }
            } else if is_from_epoch(a, state.previous_epoch(spec), spec) {
                previous_epoch.add(&attesting_indices, attesting_balance);

                if has_common_epoch_boundary_root(a, state, state.previous_epoch(spec), spec)? {
                    previous_epoch_boundary.add(&attesting_indices, attesting_balance);
                }

                if has_common_beacon_block_root(a, state, spec)? {
                    previous_epoch_head.add(&attesting_indices, attesting_balance);
                }
            }
        }

        Ok(Self {
            current_epoch,
            current_epoch_boundary,
            previous_epoch,
            previous_epoch_boundary,
            previous_epoch_head,
        })
    }
}

fn is_from_epoch(a: &PendingAttestation, epoch: Epoch, spec: &ChainSpec) -> bool {
    a.data.slot.epoch(spec.slots_per_epoch) == epoch
}

fn has_common_epoch_boundary_root(
    a: &PendingAttestation,
    state: &BeaconState,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<bool, BeaconStateError> {
    let slot = epoch.start_slot(spec.slots_per_epoch);
    let state_boundary_root = *state
        .get_block_root(slot, spec)
        .ok_or_else(|| BeaconStateError::InsufficientBlockRoots)?;

    Ok(a.data.epoch_boundary_root == state_boundary_root)
}

fn has_common_beacon_block_root(
    a: &PendingAttestation,
    state: &BeaconState,
    spec: &ChainSpec,
) -> Result<bool, BeaconStateError> {
    let state_block_root = *state
        .get_block_root(a.data.slot, spec)
        .ok_or_else(|| BeaconStateError::InsufficientBlockRoots)?;

    Ok(a.data.beacon_block_root == state_block_root)
}
