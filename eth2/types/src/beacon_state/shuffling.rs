use super::CommitteesError;
use crate::{validator_registry::get_active_validator_indices, BeaconState, ChainSpec, Hash256};
use honey_badger_split::SplitExt;
use vec_shuffle::shuffle;

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

    /// Returns the beacon proposer index for the `slot`.
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    pub fn get_beacon_proposer_index(
        &self,
        slot: u64,
        spec: &ChainSpec,
    ) -> Result<usize, CommitteesError> {
        let committees = self.get_crosslink_committees_at_slot(slot, spec)?;
        committees
            .first()
            .ok_or(CommitteesError::InsufficientNumberOfValidators)
            .and_then(|(first_committee, _)| {
                let index = (slot as usize)
                    .checked_rem(first_committee.len())
                    .ok_or(CommitteesError::InsufficientNumberOfValidators)?;
                // NOTE: next index will not panic as we have already returned if this is the case
                Ok(first_committee[index])
            })
    }
}
