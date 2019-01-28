use crate::{validator_registry::get_active_validator_indices, BeaconState, ChainSpec, Hash256};
use honey_badger_split::SplitExt;
use vec_shuffle::shuffle;

type CrosslinkCommittee = (Vec<usize>, usize);
type CrosslinkCommittees = Vec<CrosslinkCommittee>;

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
            .honey_badger_split(committees_per_slot * spec.epoch_length as usize)
            .filter_map(|slice: &[usize]| Some(slice.to_vec()))
            .collect()
    }

    pub fn get_committee_count_per_slot(
        &self,
        active_validator_count: usize,
        spec: &ChainSpec,
    ) -> usize {
        std::cmp::max(
            1,
            std::cmp::min(
                spec.shard_count as usize / spec.epoch_length as usize,
                active_validator_count
                    / spec.epoch_length as usize
                    / spec.target_committee_size as usize,
            ),
        )
    }

    pub fn get_crosslink_committees_at_slot(&self, _slot: u64) -> Option<CrosslinkCommittees> {
        Some(vec![(vec![0], 0)])
    }
}
