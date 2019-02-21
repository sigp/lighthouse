use crate::{
    validator_registry::get_active_validator_indices, BeaconState, ChainSpec, Epoch, Hash256,
};
use honey_badger_split::SplitExt;
use serde_derive::Serialize;
use swap_or_not_shuffle::get_permutated_index;

pub const CACHED_EPOCHS: usize = 3;

#[derive(Debug, PartialEq, Clone, Default, Serialize)]
pub struct CommitteesCache {
    cache_index_offset: usize,
    active_validator_indices_cache: Vec<Option<Vec<usize>>>,
    shuffling_cache: Vec<Option<Option<Vec<Vec<usize>>>>>,
    previous_epoch: Epoch,
    current_epoch: Epoch,
    next_epoch: Epoch,
}

impl CommitteesCache {
    pub fn new(current_epoch: Epoch, spec: &ChainSpec) -> Self {
        let previous_epoch = if current_epoch == spec.genesis_epoch {
            current_epoch
        } else {
            current_epoch - 1
        };
        let next_epoch = current_epoch + 1;

        Self {
            cache_index_offset: 0,
            active_validator_indices_cache: vec![None; CACHED_EPOCHS],
            shuffling_cache: vec![None; CACHED_EPOCHS],
            previous_epoch,
            current_epoch,
            next_epoch,
        }
    }

    pub fn advance_epoch(&mut self) {
        let previous_cache_index = self.cache_index(self.previous_epoch);

        self.active_validator_indices_cache[previous_cache_index] = None;
        self.shuffling_cache[previous_cache_index] = None;

        self.cache_index_offset += 1;
        self.cache_index_offset %= CACHED_EPOCHS;
    }

    pub fn cache_index(&self, epoch: Epoch) -> usize {
        let base_index = match epoch {
            e if e == self.previous_epoch => 0,
            e if e == self.current_epoch => 1,
            e if e == self.next_epoch => 2,
            _ => panic!("Bad cache index."),
        };

        (base_index + self.cache_index_offset) % CACHED_EPOCHS
    }

    pub fn get_active_validator_indices(
        &mut self,
        state: &BeaconState,
        epoch: Epoch,
    ) -> &Vec<usize> {
        let i = self.cache_index(epoch);

        if self.active_validator_indices_cache[i] == None {
            self.active_validator_indices_cache[i] = Some(get_active_validator_indices(
                &state.validator_registry,
                epoch,
            ));
        }

        self.active_validator_indices_cache[i]
            .as_ref()
            .expect("Cache cannot be None")
    }

    pub fn get_shuffling(
        &mut self,
        state: &BeaconState,
        seed: Hash256,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Option<&Vec<Vec<usize>>> {
        let cache_index = self.cache_index(epoch);

        if self.shuffling_cache[cache_index] == None {
            let active_validator_indices = self.get_active_validator_indices(&state, epoch);

            if active_validator_indices.is_empty() {
                return None;
            }

            let committees_per_epoch =
                state.get_epoch_committee_count(active_validator_indices.len(), spec);

            let mut shuffled_active_validator_indices = vec![0; active_validator_indices.len()];
            for &i in active_validator_indices {
                let shuffled_i = get_permutated_index(
                    i,
                    active_validator_indices.len(),
                    &seed[..],
                    spec.shuffle_round_count,
                )?;
                shuffled_active_validator_indices[i] = active_validator_indices[shuffled_i]
            }

            let committees: Vec<Vec<usize>> = shuffled_active_validator_indices
                .honey_badger_split(committees_per_epoch as usize)
                .map(|slice: &[usize]| slice.to_vec())
                .collect();

            self.shuffling_cache[cache_index] = Some(Some(committees));
        }

        match self.shuffling_cache[cache_index] {
            Some(_) => Some(
                self.shuffling_cache[cache_index]
                    .as_ref()
                    .expect("Cache cannot be None")
                    .as_ref()
                    .expect("Shuffling cannot be None."),
            ),
            None => None,
        }
    }
}
