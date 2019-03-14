use types::*;

macro_rules! set_self_if_other_is_true {
    ($self_: ident, $other: ident, $var: ident) => {
        $self_.$var = $other.$var & !$self_.$var;
    };
}

#[derive(Clone)]
pub struct InclusionInfo {
    pub slot: Slot,
    pub distance: Slot,
    pub proposer_index: usize,
}

impl Default for InclusionInfo {
    fn default() -> Self {
        Self {
            slot: Slot::max_value(),
            distance: Slot::max_value(),
            proposer_index: 0,
        }
    }
}

impl InclusionInfo {
    pub fn update(&mut self, other: &Self) {
        if other.slot < self.slot {
            self.slot = other.slot;
            self.distance = other.distance;
            self.proposer_index = other.proposer_index;
        }
    }
}

#[derive(Default, Clone)]
pub struct AttesterStatus {
    pub is_active: bool,

    pub is_current_epoch: bool,
    pub is_current_epoch_boundary: bool,
    pub is_previous_epoch: bool,
    pub is_previous_epoch_boundary: bool,
    pub is_previous_epoch_head: bool,

    pub inclusion_info: InclusionInfo,
}

impl AttesterStatus {
    pub fn update(&mut self, other: &Self) {
        // Update all the bool fields, only updating `self` if `other` is true (never setting
        // `self` to false).
        set_self_if_other_is_true!(self, other, is_active);
        set_self_if_other_is_true!(self, other, is_current_epoch);
        set_self_if_other_is_true!(self, other, is_current_epoch_boundary);
        set_self_if_other_is_true!(self, other, is_previous_epoch);
        set_self_if_other_is_true!(self, other, is_previous_epoch_boundary);
        set_self_if_other_is_true!(self, other, is_previous_epoch_head);

        self.inclusion_info.update(&other.inclusion_info);
    }
}

#[derive(Default, Clone)]
pub struct TotalBalances {
    pub current_epoch: u64,
    pub current_epoch_boundary: u64,
    pub previous_epoch: u64,
    pub previous_epoch_boundary: u64,
    pub previous_epoch_head: u64,
}

pub struct Attesters {
    pub statuses: Vec<AttesterStatus>,
    pub balances: TotalBalances,
}

impl Attesters {
    pub fn empty(num_validators: usize) -> Self {
        Self {
            statuses: vec![AttesterStatus::default(); num_validators],
            balances: TotalBalances::default(),
        }
    }

    pub fn process_active_validator_indices(&mut self, active_validator_indices: &[usize]) {
        let status = AttesterStatus {
            is_active: true,
            ..AttesterStatus::default()
        };

        for &i in active_validator_indices {
            self.statuses[i].update(&status);
        }
    }

    pub fn process_attestations(
        &mut self,
        state: &BeaconState,
        attestations: &[PendingAttestation],
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        for a in attestations {
            let attesting_indices =
                state.get_attestation_participants(&a.data, &a.aggregation_bitfield, spec)?;
            let attesting_balance = state.get_total_balance(&attesting_indices, spec);

            let mut status = AttesterStatus::default();

            // Profile this attestation, updating the total balances and generating an
            // `AttesterStatus` object that applies to all participants in the attestation.
            if is_from_epoch(a, state.current_epoch(spec), spec) {
                self.balances.current_epoch += attesting_balance;
                status.is_current_epoch = true;

                if has_common_epoch_boundary_root(a, state, state.current_epoch(spec), spec)? {
                    self.balances.current_epoch_boundary += attesting_balance;
                    status.is_current_epoch_boundary = true;
                }
            } else if is_from_epoch(a, state.previous_epoch(spec), spec) {
                self.balances.previous_epoch += attesting_balance;
                status.is_previous_epoch = true;

                // The inclusion slot and distance are only required for previous epoch attesters.
                status.inclusion_info = InclusionInfo {
                    slot: a.inclusion_slot,
                    distance: inclusion_distance(a),
                    proposer_index: state.get_beacon_proposer_index(a.inclusion_slot, spec)?,
                };

                if has_common_epoch_boundary_root(a, state, state.previous_epoch(spec), spec)? {
                    self.balances.previous_epoch_boundary += attesting_balance;
                    status.is_previous_epoch_boundary = true;
                }

                if has_common_beacon_block_root(a, state, spec)? {
                    self.balances.previous_epoch_head += attesting_balance;
                    status.is_previous_epoch_head = true;
                }
            }

            // Loop through the participating validator indices and update the status vec.
            for validator_index in attesting_indices {
                self.statuses[validator_index].update(&status);
            }
        }

        Ok(())
    }
}

fn inclusion_distance(a: &PendingAttestation) -> Slot {
    a.inclusion_slot - a.data.slot
}

/// Returns `true` if some `PendingAttestation` is from the supplied `epoch`.
///
/// Spec v0.4.0
fn is_from_epoch(a: &PendingAttestation, epoch: Epoch, spec: &ChainSpec) -> bool {
    a.data.slot.epoch(spec.slots_per_epoch) == epoch
}

/// Returns `true` if a `PendingAttestation` and `BeaconState` share the same beacon block hash for
/// the first slot of the given epoch.
///
/// Spec v0.4.0
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

/// Returns `true` if a `PendingAttestation` and `BeaconState` share the same beacon block hash for
/// the current slot of the `PendingAttestation`.
///
/// Spec v0.4.0
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
