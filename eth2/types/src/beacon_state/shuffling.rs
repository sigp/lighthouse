use super::Error;
use crate::{validator_registry::get_active_validator_indices, BeaconState, ChainSpec, Hash256};
use honey_badger_split::SplitExt;
use std::ops::Range;
use vec_shuffle::shuffle;

// utility function pending this functionality being stabilized on the `Range` type.
fn range_contains<T: PartialOrd>(range: &Range<T>, target: T) -> bool {
    range.start <= target && target < range.end
}

type Result<T> = std::result::Result<T, Error>;

impl BeaconState {
    pub fn get_shuffling(&self, seed: Hash256, slot: u64, spec: &ChainSpec) -> Vec<Vec<usize>> {
        let slot = slot - (slot % spec.epoch_length);

        let active_validator_indices = get_active_validator_indices(&self.validator_registry, slot);

        let committees_per_slot =
            self.get_committee_count_per_slot(active_validator_indices.len(), spec);

        // TODO: check that Hash256 matches 'int_to_bytes32'.
        let seed = seed ^ Hash256::from(slot);
        let shuffled_active_validator_indices =
            shuffle(&seed, active_validator_indices).expect("Max validator count exceed!");

        shuffled_active_validator_indices
            .honey_badger_split((committees_per_slot * spec.epoch_length) as usize)
            .filter_map(|slice: &[usize]| Some(slice.to_vec()))
            .collect()
    }

    pub fn get_committee_count_per_slot(
        &self,
        active_validator_count: usize,
        spec: &ChainSpec,
    ) -> u64 {
        std::cmp::max(
            1,
            std::cmp::min(
                spec.shard_count / spec.epoch_length,
                active_validator_count as u64 / spec.epoch_length / spec.target_committee_size,
            ),
        )
    }

    /// Returns the start slot and end slot of the current epoch containing `self.slot`.
    fn get_current_epoch_boundaries(&self, epoch_length: u64) -> Range<u64> {
        let slot_in_epoch = self.slot % epoch_length;
        let start = self.slot - slot_in_epoch;
        let end = self.slot + (epoch_length - slot_in_epoch);
        start..end
    }

    fn get_previous_epoch_committee_count_per_slot(
        &self,
        spec: &ChainSpec,
        /*
        shard_count: u64,
        epoch_length: u64,
        target_committee_size: u64,
        */
    ) -> u64 {
        let previous_active_validators = get_active_validator_indices(
            &self.validator_registry,
            self.previous_epoch_calculation_slot,
        );
        self.get_committee_count_per_slot(previous_active_validators.len(), spec) as u64
    }

    pub fn get_current_epoch_committee_count_per_slot(&self, spec: &ChainSpec) -> u64 {
        let current_active_validators = get_active_validator_indices(
            &self.validator_registry,
            self.current_epoch_calculation_slot,
        );
        self.get_committee_count_per_slot(current_active_validators.len(), spec)
    }

    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: u64,
        spec: &ChainSpec,
        /*
        epoch_length: u64,
        shard_count: u64,
        target_committee_size: u64,
        */
    ) -> Result<Vec<(Vec<usize>, u64)>> {
        let current_epoch_range = self.get_current_epoch_boundaries(spec.epoch_length);
        if !range_contains(&current_epoch_range, slot) {
            return Err(Error::InvalidSlot);
        }
        let state_epoch_slot = current_epoch_range.start;
        let offset = slot % spec.epoch_length;

        let (committees_per_slot, shuffling, slot_start_shard) = if slot < state_epoch_slot {
            let committees_per_slot = self.get_previous_epoch_committee_count_per_slot(spec);
            let shuffling = self.get_shuffling(
                self.previous_epoch_seed,
                self.previous_epoch_calculation_slot,
                spec,
            );
            let slot_start_shard =
                (self.previous_epoch_start_shard + committees_per_slot * offset) % spec.shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        } else {
            let committees_per_slot = self.get_current_epoch_committee_count_per_slot(spec);
            let shuffling = self.get_shuffling(
                self.current_epoch_seed,
                self.current_epoch_calculation_slot,
                spec,
            );
            let slot_start_shard =
                (self.current_epoch_start_shard + committees_per_slot * offset) % spec.shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        };

        let shard_range = slot_start_shard..;
        Ok(shuffling
            .into_iter()
            .skip((committees_per_slot * offset) as usize)
            .zip(shard_range.into_iter())
            .take(committees_per_slot as usize)
            .map(|(committees, shard_number)| (committees, shard_number % spec.shard_count))
            .collect::<Vec<_>>())
    }

    /// Returns the beacon proposer index for the `slot`.
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    pub fn get_beacon_proposer_index(&self, slot: u64, spec: &ChainSpec) -> Result<usize> {
        let committees = self.get_crosslink_committees_at_slot(slot, spec)?;
        committees
            .first()
            .ok_or(Error::InsufficientNumberOfValidators)
            .and_then(|(first_committee, _)| {
                let index = (slot as usize)
                    .checked_rem(first_committee.len())
                    .ok_or(Error::InsufficientNumberOfValidators)?;
                // NOTE: next index will not panic as we have already returned if this is the case
                Ok(first_committee[index])
            })
    }
}
