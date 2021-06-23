use safe_arith::ArithError;
use std::collections::HashMap;
use types::{
    consts::altair::NUM_FLAG_INDICES, BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec,
    ParticipationFlags,
};

pub struct ParticipationCache {
    current_epoch: Epoch,
    current_epoch_map: HashMap<usize, ParticipationFlags>,
    previous_epoch: Epoch,
    previous_epoch_map: HashMap<usize, ParticipationFlags>,
}

impl ParticipationCache {
    pub fn altair<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        Ok(Self {
            current_epoch,
            current_epoch_map: get_epoch_participation(state, current_epoch, spec)?,
            previous_epoch,
            previous_epoch_map: get_epoch_participation(state, previous_epoch, spec)?,
        })
    }

    pub fn get_unslashed_participating_indices(
        &self,
        flag_index: usize,
        epoch: Epoch,
    ) -> Result<UnslashedParticipatingIndices, BeaconStateError> {
        let map = if epoch == self.current_epoch {
            &self.current_epoch_map
        } else if epoch == self.previous_epoch {
            &self.previous_epoch_map
        } else {
            return Err(BeaconStateError::EpochOutOfBounds);
        };

        // Note: protects the iterator.
        if flag_index >= NUM_FLAG_INDICES {
            return Err(ArithError::Overflow.into());
        }

        Ok(UnslashedParticipatingIndices { map, flag_index })
    }
}

pub struct UnslashedParticipatingIndices<'a> {
    map: &'a HashMap<usize, ParticipationFlags>,
    flag_index: usize,
}

impl<'a> UnslashedParticipatingIndices<'a> {
    pub fn contains(&self, val_index: usize) -> Result<bool, ArithError> {
        self.map
            .get(&val_index)
            .map(|participation_flags| participation_flags.has_flag(self.flag_index))
            .unwrap_or(Ok(false))
    }
}

pub struct UnslashedParticipatingIndicesIter<'a> {
    iter: std::collections::hash_map::Iter<'a, usize, ParticipationFlags>,
    flag_index: usize,
}

impl<'a> Iterator for UnslashedParticipatingIndicesIter<'a> {
    type Item = &'a usize;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((val_index, participation_flags)) = self.iter.next() {
            if participation_flags
                .has_flag(self.flag_index)
                .unwrap_or(false)
            {
                return Some(val_index);
            }
        }

        None
    }
}

impl<'a> IntoIterator for &'a UnslashedParticipatingIndices<'a> {
    type Item = &'a usize;
    type IntoIter = UnslashedParticipatingIndicesIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // todo: check flag is legit.
        UnslashedParticipatingIndicesIter {
            iter: self.map.iter(),
            flag_index: self.flag_index,
        }
    }
}

fn get_epoch_participation<T: EthSpec>(
    state: &BeaconState<T>,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<HashMap<usize, ParticipationFlags>, BeaconStateError> {
    let epoch_participation = if epoch == state.current_epoch() {
        state.current_epoch_participation()?
    } else if epoch == state.previous_epoch() {
        state.previous_epoch_participation()?
    } else {
        return Err(BeaconStateError::EpochOutOfBounds);
    };

    // Might be too large due to slashed boiz.
    let active_validator_indices = state.get_active_validator_indices(epoch, spec)?;
    let mut map = HashMap::with_capacity(active_validator_indices.len());

    for val_index in active_validator_indices {
        if !state.get_validator(val_index)?.slashed {
            map.insert(
                val_index,
                *epoch_participation
                    .get(val_index)
                    .ok_or(BeaconStateError::ParticipationOutOfBounds(val_index))?,
            );
        }
    }

    Ok(map)
}
