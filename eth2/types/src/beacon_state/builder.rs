use super::BeaconStateError;
use crate::*;
use crate::{validator_registry::get_active_validator_indices, *};
use bls::create_proof_of_possession;
use rayon::prelude::*;
use ssz::TreeHash;

/// Builds a `BeaconState` for use in testing or benchmarking.
///
/// Building the `BeaconState` is a three step processes:
///
/// 1. Create a new `BeaconStateBuilder`.
/// 2. Call `Self::build()` or `Self::build_fast()` generate a  `BeaconState`.
/// 3. (Optional) Use builder functions to modify the `BeaconState`.
/// 4. Call `Self::cloned_state()` to obtain a `BeaconState` cloned from this struct.
///
/// Step (2) happens prior to step (3) because some functionality requires an existing
/// `BeaconState`.
///
/// Step (4) produces a clone of the BeaconState and doesn't consume the `BeaconStateBuilder` to
/// allow access to `self.keypairs` and `self.spec`.
pub struct BeaconStateBuilder {
    pub state: BeaconState,
}

impl BeaconStateBuilder {
    /// Create a new builder with the given number of validators.
    ///
    /// Spec v0.4.0
    pub fn new(genesis_time: u64, latest_eth1_data: Eth1Data, spec: &ChainSpec) -> Self {
        Self {
            state: BeaconState::genesis(genesis_time, latest_eth1_data, spec),
        }
    }

    /// Produce the first state of the Beacon Chain.
    ///
    /// Spec v0.4.0
    pub fn process_initial_deposits(
        &mut self,
        initial_validator_deposits: &[Deposit],
        spec: &ChainSpec,
    ) {
        let deposit_data = initial_validator_deposits
            .par_iter()
            .map(|deposit| &deposit.deposit_data)
            .collect();

        self.state.process_deposits(deposit_data, spec);

        for validator_index in 0..self.state.validator_registry.len() {
            if self.state.get_effective_balance(validator_index, spec) >= spec.max_deposit_amount {
                self.state.activate_validator(validator_index, true, spec);
            }
        }

        self.state.deposit_index = initial_validator_deposits.len() as u64;
    }

    /// Builds a `BeaconState` using the `BeaconState::genesis(..)` function.
    ///
    /// Each validator is assigned a unique, randomly-generated keypair and all
    /// proof-of-possessions are verified during genesis.
    ///
    /// Spec v0.4.0
    pub fn build(mut self, spec: &ChainSpec) -> Result<BeaconState, BeaconStateError> {
        let genesis_active_index_root =
            get_active_validator_indices(&self.state.validator_registry, spec.genesis_epoch)
                .hash_tree_root();

        self.state.latest_active_index_roots = vec![
            Hash256::from_slice(&genesis_active_index_root);
            spec.latest_active_index_roots_length
        ];

        self.state.current_shuffling_seed = self.state.generate_seed(spec.genesis_epoch, spec)?;

        Ok(self.state)
    }

    /*
    /// Sets the `BeaconState` to be in the last slot of the given epoch.
    ///
    /// Sets all justification/finalization parameters to be be as "perfect" as possible (i.e.,
    /// highest justified and finalized slots, full justification bitfield, etc).
    pub fn teleport_to_end_of_epoch(&mut self, epoch: Epoch, spec: &ChainSpec) {
        let state = &mut self.state;

        let slot = epoch.end_slot(spec.slots_per_epoch);

        state.slot = slot;
        state.validator_registry_update_epoch = epoch - 1;

        state.previous_shuffling_epoch = epoch - 1;
        state.current_shuffling_epoch = epoch;

        state.previous_shuffling_seed = Hash256::from_low_u64_le(0);
        state.current_shuffling_seed = Hash256::from_low_u64_le(1);

        state.previous_justified_epoch = epoch - 2;
        state.justified_epoch = epoch - 1;
        state.justification_bitfield = u64::max_value();
        state.finalized_epoch = epoch - 1;
    }

    /// Creates a full set of attestations for the `BeaconState`. Each attestation has full
    /// participation from its committee and references the expected beacon_block hashes.
    ///
    /// These attestations should be fully conducive to justification and finalization.
    pub fn insert_attestations(&mut self) {
        let state = &mut self.state;

        state
            .build_epoch_cache(RelativeEpoch::Previous, &self.spec)
            .unwrap();
        state
            .build_epoch_cache(RelativeEpoch::Current, &self.spec)
            .unwrap();

        let current_epoch = state.current_epoch(&self.spec);
        let previous_epoch = state.previous_epoch(&self.spec);
        let current_epoch_depth =
            (state.slot - current_epoch.end_slot(self.spec.slots_per_epoch)).as_usize();

        let previous_epoch_slots = previous_epoch.slot_iter(self.spec.slots_per_epoch);
        let current_epoch_slots = current_epoch
            .slot_iter(self.spec.slots_per_epoch)
            .take(current_epoch_depth);

        for slot in previous_epoch_slots.chain(current_epoch_slots) {
            let committees = state
                .get_crosslink_committees_at_slot(slot, &self.spec)
                .unwrap()
                .clone();

            for (committee, shard) in committees {
                state
                    .latest_attestations
                    .push(committee_to_pending_attestation(
                        state, &committee, shard, slot, &self.spec,
                    ))
            }
        }
    }

    /// Returns a cloned `BeaconState`.
    pub fn cloned_state(&self) -> BeaconState {
        self.state.as_ref().expect("Genesis required").clone()
    }
    */
}

/*
/// Builds a valid PendingAttestation with full participation for some committee.
fn committee_to_pending_attestation(
    state: &BeaconState,
    committee: &[usize],
    shard: u64,
    slot: Slot,
    spec: &ChainSpec,
) -> PendingAttestation {
    let current_epoch = state.current_epoch(spec);
    let previous_epoch = state.previous_epoch(spec);

    let mut aggregation_bitfield = Bitfield::new();
    let mut custody_bitfield = Bitfield::new();

    for (i, _) in committee.iter().enumerate() {
        aggregation_bitfield.set(i, true);
        custody_bitfield.set(i, true);
    }

    let is_previous_epoch =
        state.slot.epoch(spec.slots_per_epoch) != slot.epoch(spec.slots_per_epoch);

    let justified_epoch = if is_previous_epoch {
        state.previous_justified_epoch
    } else {
        state.justified_epoch
    };

    let epoch_boundary_root = if is_previous_epoch {
        *state
            .get_block_root(previous_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap()
    } else {
        *state
            .get_block_root(current_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap()
    };

    let justified_block_root = *state
        .get_block_root(justified_epoch.start_slot(spec.slots_per_epoch), &spec)
        .unwrap();

    PendingAttestation {
        aggregation_bitfield,
        data: AttestationData {
            slot,
            shard,
            beacon_block_root: *state.get_block_root(slot, spec).unwrap(),
            epoch_boundary_root,
            crosslink_data_root: Hash256::zero(),
            latest_crosslink: Crosslink {
                epoch: slot.epoch(spec.slots_per_epoch),
                crosslink_data_root: Hash256::zero(),
            },
            justified_epoch,
            justified_block_root,
        },
        custody_bitfield,
        inclusion_slot: slot,
    }
}
*/
