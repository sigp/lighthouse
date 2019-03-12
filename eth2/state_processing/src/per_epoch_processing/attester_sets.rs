use fnv::FnvHashSet;
use types::*;

/// A set of validator indices, along with the total balance of all those attesters.
#[derive(Default)]
pub struct Attesters {
    /// A set of validator indices.
    pub indices: FnvHashSet<usize>,
    /// The total balance of all validators in `self.indices`.
    pub balance: u64,
}

impl Attesters {
    /// Add the given indices to the set, incrementing the sets balance by the provided balance.
    fn add(&mut self, additional_indices: &[usize], additional_balance: u64) {
        self.indices.reserve(additional_indices.len());
        for i in additional_indices {
            self.indices.insert(*i);
        }
        self.balance = self.balance.saturating_add(additional_balance);
    }
}

/// A collection of `Attester` objects, representing set of attesters that are rewarded/penalized
/// during an epoch transition.
pub struct AttesterSets {
    /// All validators who attested during the state's current epoch.
    pub current_epoch: Attesters,
    /// All validators who attested that the beacon block root of the first slot of the state's
    /// current epoch is the same as the one stored in this state.
    ///
    /// In short validators who agreed with the state about the first slot of the current epoch.
    pub current_epoch_boundary: Attesters,
    /// All validators who attested during the state's previous epoch.
    pub previous_epoch: Attesters,
    /// All validators who attested that the beacon block root of the first slot of the state's
    /// previous epoch is the same as the one stored in this state.
    ///
    /// In short, validators who agreed with the state about the first slot of the previous epoch.
    pub previous_epoch_boundary: Attesters,
    /// All validators who attested that the beacon block root at the pending attestation's slot is
    /// the same as the one stored in this state.
    ///
    /// In short, validators who agreed with the state about the current beacon block root when
    /// they attested.
    pub previous_epoch_head: Attesters,
}

impl AttesterSets {
    /// Loop through all attestations in the state and instantiate a complete `AttesterSets` struct.
    ///
    /// Spec v0.4.0
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
