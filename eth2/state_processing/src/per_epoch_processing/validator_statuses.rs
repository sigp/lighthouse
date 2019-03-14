use super::WinningRootHashSet;
use types::*;

/// Sets the boolean `var` on `self` to be true if it is true on `other`. Otherwise leaves `self`
/// as is.
macro_rules! set_self_if_other_is_true {
    ($self_: ident, $other: ident, $var: ident) => {
        if $other.$var {
            $self_.$var = true;
        }
    };
}

/// The information required to reward some validator for their participation in a "winning"
/// crosslink root.
#[derive(Default, Clone)]
pub struct WinningRootInfo {
    /// The total balance of the crosslink committee.
    pub total_committee_balance: u64,
    /// The total balance of the crosslink committee that attested for the "winning" root.
    pub total_attesting_balance: u64,
}

/// The information required to reward a block producer for including an attestation in a block.
#[derive(Clone)]
pub struct InclusionInfo {
    /// The earliest slot a validator had an attestation included in the previous epoch.
    pub slot: Slot,
    /// The distance between the attestation slot and the slot that attestation was included in a
    /// block.
    pub distance: Slot,
    /// The index of the proposer at the slot where the attestation was included.
    pub proposer_index: usize,
}

impl Default for InclusionInfo {
    /// Defaults to `slot` and `distance` at their maximum values and `proposer_index` at zero.
    fn default() -> Self {
        Self {
            slot: Slot::max_value(),
            distance: Slot::max_value(),
            proposer_index: 0,
        }
    }
}

impl InclusionInfo {
    /// Tests if some `other` `InclusionInfo` has a lower inclusion slot than `self`. If so,
    /// replaces `self` with `other`.
    pub fn update(&mut self, other: &Self) {
        if other.slot < self.slot {
            self.slot = other.slot;
            self.distance = other.distance;
            self.proposer_index = other.proposer_index;
        }
    }
}

/// Information required to reward some validator during the current and previous epoch.
#[derive(Default, Clone)]
pub struct AttesterStatus {
    /// True if the validator was active in the state's _current_ epoch.
    pub is_active_in_current_epoch: bool,
    /// True if the validator was active in the state's _previous_ epoch.
    pub is_active_in_previous_epoch: bool,

    /// True if the validator had an attestation included in the _current_ epoch.
    pub is_current_epoch_attester: bool,
    /// True if the validator's beacon block root attestation for the first slot of the _current_
    /// epoch matches the block root known to the state.
    pub is_current_epoch_boundary_attester: bool,
    /// True if the validator had an attestation included in the _previous_ epoch.
    pub is_previous_epoch_attester: bool,
    /// True if the validator's beacon block root attestation for the first slot of the _previous_
    /// epoch matches the block root known to the state.
    pub is_previous_epoch_boundary_attester: bool,
    /// True if the validator's beacon block root attestation in the _previous_ epoch at the
    /// attestation's slot (`attestation_data.slot`) matches the block root known to the state.
    pub is_previous_epoch_head_attester: bool,

    /// Information used to reward the block producer of this validators earliest-included
    /// attestation.
    pub inclusion_info: InclusionInfo,
    /// Information used to reward/penalize the validator if they voted in the super-majority for
    /// some shard block.
    pub winning_root_info: Option<WinningRootInfo>,
}

impl AttesterStatus {
    /// Accepts some `other` `AttesterStatus` and updates `self` if required.
    ///
    /// Will never set one of the `bool` fields to `false`, it will only set it to `true` if other
    /// contains a `true` field.
    ///
    /// Note: does not update the winning root info, this is done manually.
    pub fn update(&mut self, other: &Self) {
        // Update all the bool fields, only updating `self` if `other` is true (never setting
        // `self` to false).
        set_self_if_other_is_true!(self, other, is_active_in_current_epoch);
        set_self_if_other_is_true!(self, other, is_active_in_previous_epoch);
        set_self_if_other_is_true!(self, other, is_current_epoch_attester);
        set_self_if_other_is_true!(self, other, is_current_epoch_boundary_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_boundary_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_head_attester);

        self.inclusion_info.update(&other.inclusion_info);
    }
}

/// The total effective balances for different sets of validators during the previous and current
/// epochs.
#[derive(Default, Clone)]
pub struct TotalBalances {
    /// The total effective balance of all active validators during the _current_ epoch.
    pub current_epoch: u64,
    /// The total effective balance of all active validators during the _previous_ epoch.
    pub previous_epoch: u64,
    /// The total effective balance of all validators who attested during the _current_ epoch.
    pub current_epoch_attesters: u64,
    /// The total effective balance of all validators who attested during the _current_ epoch and
    /// agreed with the state about the beacon block at the first slot of the _current_ epoch.
    pub current_epoch_boundary_attesters: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch.
    pub previous_epoch_attesters: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch and
    /// agreed with the state about the beacon block at the first slot of the _previous_ epoch.
    pub previous_epoch_boundary_attesters: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch and
    /// agreed with the state about the beacon block at the time of attestation.
    pub previous_epoch_head_attesters: u64,
}

/// Summarised information about validator participation in the _previous and _current_ epochs of
/// some `BeaconState`.
#[derive(Clone)]
pub struct ValidatorStatuses {
    /// Information about each individual validator from the state's validator registy.
    pub statuses: Vec<AttesterStatus>,
    /// Summed balances for various sets of validators.
    pub total_balances: TotalBalances,
}

impl ValidatorStatuses {
    /// Initializes a new instance, determining:
    ///
    /// - Active validators
    /// - Total balances for the current and previous epochs.
    ///
    /// Spec v0.4.0
    pub fn new(state: &BeaconState, spec: &ChainSpec) -> Self {
        let mut statuses = Vec::with_capacity(state.validator_registry.len());
        let mut total_balances = TotalBalances::default();

        for (i, validator) in state.validator_registry.iter().enumerate() {
            let mut status = AttesterStatus::default();

            if validator.is_active_at(state.current_epoch(spec)) {
                status.is_active_in_current_epoch = true;
                total_balances.current_epoch += state.get_effective_balance(i, spec);
            }

            if validator.is_active_at(state.previous_epoch(spec)) {
                status.is_active_in_previous_epoch = true;
                total_balances.previous_epoch += state.get_effective_balance(i, spec);
            }

            statuses.push(status);
        }

        Self {
            statuses,
            total_balances,
        }
    }

    /// Process some attestations from the given `state` updating the `statuses` and
    /// `total_balances` fields.
    ///
    /// Spec v0.4.0
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
                self.total_balances.current_epoch_attesters += attesting_balance;
                status.is_current_epoch_attester = true;

                if has_common_epoch_boundary_root(a, state, state.current_epoch(spec), spec)? {
                    self.total_balances.current_epoch_boundary_attesters += attesting_balance;
                    status.is_current_epoch_boundary_attester = true;
                }
            } else if is_from_epoch(a, state.previous_epoch(spec), spec) {
                self.total_balances.previous_epoch_attesters += attesting_balance;
                status.is_previous_epoch_attester = true;

                // The inclusion slot and distance are only required for previous epoch attesters.
                status.inclusion_info = InclusionInfo {
                    slot: a.inclusion_slot,
                    distance: inclusion_distance(a),
                    proposer_index: state.get_beacon_proposer_index(a.inclusion_slot, spec)?,
                };

                if has_common_epoch_boundary_root(a, state, state.previous_epoch(spec), spec)? {
                    self.total_balances.previous_epoch_boundary_attesters += attesting_balance;
                    status.is_previous_epoch_boundary_attester = true;
                }

                if has_common_beacon_block_root(a, state, spec)? {
                    self.total_balances.previous_epoch_head_attesters += attesting_balance;
                    status.is_previous_epoch_head_attester = true;
                }
            }

            // Loop through the participating validator indices and update the status vec.
            for validator_index in attesting_indices {
                self.statuses[validator_index].update(&status);
            }
        }

        Ok(())
    }

    /// Update the `statuses` for each validator based upon whether or not they attested to the
    /// "winning" shard block root for the previous epoch.
    ///
    /// Spec v0.4.0
    pub fn process_winning_roots(
        &mut self,
        state: &BeaconState,
        winning_roots: &WinningRootHashSet,
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        // Loop through each slot in the previous epoch.
        for slot in state.previous_epoch(spec).slot_iter(spec.slots_per_epoch) {
            let crosslink_committees_at_slot =
                state.get_crosslink_committees_at_slot(slot, spec)?;

            // Loop through each committee in the slot.
            for (crosslink_committee, shard) in crosslink_committees_at_slot {
                // If there was some winning crosslink root for the committee's shard.
                if let Some(winning_root) = winning_roots.get(&shard) {
                    let total_committee_balance =
                        state.get_total_balance(&crosslink_committee, spec);
                    for &validator_index in &winning_root.attesting_validator_indices {
                        // Take note of the balance information for the winning root, it will be
                        // used later to calculate rewards for that validator.
                        self.statuses[validator_index].winning_root_info = Some(WinningRootInfo {
                            total_committee_balance,
                            total_attesting_balance: winning_root.total_attesting_balance,
                        })
                    }
                }
            }
        }

        Ok(())
    }
}

/// Returns the distance between when the attestation was created and when it was included in a
/// block.
///
/// Spec v0.4.0
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
