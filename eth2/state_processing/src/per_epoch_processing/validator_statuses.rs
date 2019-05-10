use super::get_attestation_participants::get_attestation_participants;
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
#[derive(Clone, Copy)]
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
pub struct ValidatorStatus {
    /// True if the validator has been slashed, ever.
    pub is_slashed: bool,
    /// True if the validator can withdraw in the current epoch.
    pub is_withdrawable_in_current_epoch: bool,
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
    pub inclusion_info: Option<InclusionInfo>,
    /// Information used to reward/penalize the validator if they voted in the super-majority for
    /// some shard block.
    pub winning_root_info: Option<WinningRootInfo>,
}

impl ValidatorStatus {
    /// Accepts some `other` `ValidatorStatus` and updates `self` if required.
    ///
    /// Will never set one of the `bool` fields to `false`, it will only set it to `true` if other
    /// contains a `true` field.
    ///
    /// Note: does not update the winning root info, this is done manually.
    pub fn update(&mut self, other: &Self) {
        // Update all the bool fields, only updating `self` if `other` is true (never setting
        // `self` to false).
        set_self_if_other_is_true!(self, other, is_slashed);
        set_self_if_other_is_true!(self, other, is_withdrawable_in_current_epoch);
        set_self_if_other_is_true!(self, other, is_active_in_current_epoch);
        set_self_if_other_is_true!(self, other, is_active_in_previous_epoch);
        set_self_if_other_is_true!(self, other, is_current_epoch_attester);
        set_self_if_other_is_true!(self, other, is_current_epoch_boundary_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_boundary_attester);
        set_self_if_other_is_true!(self, other, is_previous_epoch_head_attester);

        if let Some(other_info) = other.inclusion_info {
            if let Some(self_info) = self.inclusion_info.as_mut() {
                self_info.update(&other_info);
            } else {
                self.inclusion_info = other.inclusion_info;
            }
        }
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
    pub statuses: Vec<ValidatorStatus>,
    /// Summed balances for various sets of validators.
    pub total_balances: TotalBalances,
}

impl ValidatorStatuses {
    /// Initializes a new instance, determining:
    ///
    /// - Active validators
    /// - Total balances for the current and previous epochs.
    ///
    /// Spec v0.5.1
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let mut statuses = Vec::with_capacity(state.validator_registry.len());
        let mut total_balances = TotalBalances::default();

        for (i, validator) in state.validator_registry.iter().enumerate() {
            let mut status = ValidatorStatus {
                is_slashed: validator.slashed,
                is_withdrawable_in_current_epoch: validator
                    .is_withdrawable_at(state.current_epoch(spec)),
                ..ValidatorStatus::default()
            };

            if validator.is_active_at(state.current_epoch(spec)) {
                status.is_active_in_current_epoch = true;
                total_balances.current_epoch += state.get_effective_balance(i, spec)?;
            }

            if validator.is_active_at(state.previous_epoch(spec)) {
                status.is_active_in_previous_epoch = true;
                total_balances.previous_epoch += state.get_effective_balance(i, spec)?;
            }

            statuses.push(status);
        }

        Ok(Self {
            statuses,
            total_balances,
        })
    }

    /// Process some attestations from the given `state` updating the `statuses` and
    /// `total_balances` fields.
    ///
    /// Spec v0.5.1
    pub fn process_attestations<T: EthSpec>(
        &mut self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        for a in state
            .previous_epoch_attestations
            .iter()
            .chain(state.current_epoch_attestations.iter())
        {
            let attesting_indices =
                get_attestation_participants(state, &a.data, &a.aggregation_bitfield, spec)?;
            let attesting_balance = state.get_total_balance(&attesting_indices, spec)?;

            let mut status = ValidatorStatus::default();

            // Profile this attestation, updating the total balances and generating an
            // `ValidatorStatus` object that applies to all participants in the attestation.
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
                let relative_epoch = RelativeEpoch::from_slot(state.slot, a.inclusion_slot, spec)?;
                status.inclusion_info = Some(InclusionInfo {
                    slot: a.inclusion_slot,
                    distance: inclusion_distance(a),
                    proposer_index: state.get_beacon_proposer_index(
                        a.inclusion_slot,
                        relative_epoch,
                        spec,
                    )?,
                });

                if has_common_epoch_boundary_root(a, state, state.previous_epoch(spec), spec)? {
                    self.total_balances.previous_epoch_boundary_attesters += attesting_balance;
                    status.is_previous_epoch_boundary_attester = true;
                }

                if has_common_beacon_block_root(a, state)? {
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
    /// Spec v0.5.1
    pub fn process_winning_roots<T: EthSpec>(
        &mut self,
        state: &BeaconState<T>,
        winning_roots: &WinningRootHashSet,
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        // Loop through each slot in the previous epoch.
        for slot in state.previous_epoch(spec).slot_iter(spec.slots_per_epoch) {
            let crosslink_committees_at_slot =
                state.get_crosslink_committees_at_slot(slot, spec)?;

            // Loop through each committee in the slot.
            for c in crosslink_committees_at_slot {
                // If there was some winning crosslink root for the committee's shard.
                if let Some(winning_root) = winning_roots.get(&c.shard) {
                    let total_committee_balance = state.get_total_balance(&c.committee, spec)?;
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
/// Spec v0.5.1
fn inclusion_distance(a: &PendingAttestation) -> Slot {
    a.inclusion_slot - a.data.slot
}

/// Returns `true` if some `PendingAttestation` is from the supplied `epoch`.
///
/// Spec v0.5.1
fn is_from_epoch(a: &PendingAttestation, epoch: Epoch, spec: &ChainSpec) -> bool {
    a.data.slot.epoch(spec.slots_per_epoch) == epoch
}

/// Returns `true` if a `PendingAttestation` and `BeaconState` share the same beacon block hash for
/// the first slot of the given epoch.
///
/// Spec v0.5.1
fn has_common_epoch_boundary_root<T: EthSpec>(
    a: &PendingAttestation,
    state: &BeaconState<T>,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<bool, BeaconStateError> {
    let slot = epoch.start_slot(spec.slots_per_epoch);
    let state_boundary_root = *state.get_block_root(slot)?;

    Ok(a.data.target_root == state_boundary_root)
}

/// Returns `true` if a `PendingAttestation` and `BeaconState` share the same beacon block hash for
/// the current slot of the `PendingAttestation`.
///
/// Spec v0.5.1
fn has_common_beacon_block_root<T: EthSpec>(
    a: &PendingAttestation,
    state: &BeaconState<T>,
) -> Result<bool, BeaconStateError> {
    let state_block_root = *state.get_block_root(a.data.slot)?;

    Ok(a.data.beacon_block_root == state_block_root)
}
