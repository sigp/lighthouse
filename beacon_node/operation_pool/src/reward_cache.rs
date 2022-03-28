use crate::OpPoolError;
use std::collections::HashMap;
use types::{BeaconState, BeaconStateError, Epoch, EthSpec, Hash256, ParticipationFlags};

#[derive(Debug, Clone)]
struct Initialization {
    current_epoch: Epoch,
    prev_epoch_last_block_root: Hash256,
    latest_block_root: Hash256,
}

/// Cache to store validator effective balances and base rewards for block proposal.
#[derive(Debug, Clone, Default)]
pub struct RewardCache {
    initialization: Option<Initialization>,
    /// Map from validator index to `effective_balance`.
    effective_balances: HashMap<usize, u64>,
    /// Map from validator index to participation flags for the previous epoch.
    ///
    /// Validators with non-zero participation for the previous epoch are omitted from this map
    /// in order to keep its memory-usage as small as possible.
    ///
    // FIXME(sproul): choose between handling slashable attestations (keep all non-complete) and
    // memory efficiency (keep all zero).
    // FIXME(sproul): choose whether to filter inactive validators
    previous_epoch_participation: HashMap<usize, ParticipationFlags>,
    /// Map from validator index to participation flags for the current epoch.
    ///
    /// Validators with complete participation for the current epoch are omitted from this map
    /// in order to keep its memory-usage as small as possible.
    current_epoch_participation: HashMap<usize, ParticipationFlags>,
}

impl RewardCache {
    pub fn get_effective_balance(&self, validator_index: usize) -> Option<u64> {
        self.effective_balances.get(&validator_index).copied()
    }

    pub fn get_epoch_participation(
        &self,
        validator_index: usize,
        epoch: Epoch,
    ) -> Result<Option<ParticipationFlags>, OpPoolError> {
        if let Some(init) = &self.initialization {
            if init.current_epoch == epoch {
                Ok(self
                    .current_epoch_participation
                    .get(&validator_index)
                    .copied())
            } else if init.current_epoch == epoch + 1 {
                Ok(self
                    .previous_epoch_participation
                    .get(&validator_index)
                    .copied())
            } else {
                Err(OpPoolError::RewardCacheWrongEpoch)
            }
        } else {
            Err(OpPoolError::RewardCacheWrongEpoch)
        }
    }

    /// Update the cache.
    pub fn update<E: EthSpec>(&mut self, state: &BeaconState<E>) -> Result<(), OpPoolError> {
        let current_epoch = state.current_epoch();
        let prev_epoch_last_block_root = *state
            .get_block_root(state.previous_epoch().start_slot(E::slots_per_epoch()))
            .map_err(OpPoolError::RewardCacheGetBlockRoot)?;
        let latest_block_root = *state
            .get_block_root(state.slot() - 1)
            .map_err(OpPoolError::RewardCacheGetBlockRoot)?;

        // If the `state` is from a new epoch or a different fork with a different last epoch block,
        // then update the effective balance cache (the effective balances are liable to have
        // changed at the epoch boundary).
        //
        // Similarly, update the previous epoch participation cache as previous epoch participation
        // is now fixed.
        if self.initialization.as_ref().map_or(true, |init| {
            init.current_epoch != current_epoch
                || init.prev_epoch_last_block_root != prev_epoch_last_block_root
        }) {
            self.update_effective_balances(state);
            self.update_previous_epoch_participation(state)
                .map_err(OpPoolError::RewardCacheUpdatePrevEpoch)?;
        }

        // The current epoch participation flags change every block, and will almost always need
        // updating when this function is called at a new slot.
        if self
            .initialization
            .as_ref()
            .map_or(true, |init| init.latest_block_root != latest_block_root)
        {
            self.update_current_epoch_participation(state)
                .map_err(OpPoolError::RewardCacheUpdateCurrEpoch)?;
        }

        self.initialization = Some(Initialization {
            current_epoch,
            prev_epoch_last_block_root,
            latest_block_root,
        });

        Ok(())
    }

    fn update_effective_balances<E: EthSpec>(&mut self, state: &BeaconState<E>) {
        self.effective_balances = state
            .validators()
            .iter()
            .enumerate()
            .map(|(i, val)| (i, val.effective_balance))
            .collect();
    }

    fn update_previous_epoch_participation<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
    ) -> Result<(), BeaconStateError> {
        let default_participation = ParticipationFlags::default();
        self.previous_epoch_participation = state
            .previous_epoch_participation()?
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, participation)| *participation == default_participation)
            .collect();
        Ok(())
    }

    fn update_current_epoch_participation<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
    ) -> Result<(), BeaconStateError> {
        let default_participation = ParticipationFlags::default();
        self.current_epoch_participation = state
            .current_epoch_participation()?
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, participation)| *participation == default_participation)
            .collect();
        Ok(())
    }
}
