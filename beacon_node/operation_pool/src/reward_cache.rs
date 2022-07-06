use crate::OpPoolError;
use bitvec::vec::BitVec;
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
    /// `BitVec` of validator indices which don't have default participation flags for the prev. epoch.
    ///
    /// We choose to only track whether validators have *any* participation flag set because
    /// it's impossible to include a new attestation which is better than the existing participation
    /// UNLESS the validator makes a slashable attestation, and we assume that this is rare enough
    /// that it's acceptable to be slightly sub-optimal in this case.
    previous_epoch_participation: BitVec,
    /// `BitVec` of validator indices which don't have default participation flags for the current epoch.
    current_epoch_participation: BitVec,
}

impl RewardCache {
    pub fn has_attested_in_epoch(
        &self,
        validator_index: u64,
        epoch: Epoch,
    ) -> Result<bool, OpPoolError> {
        if let Some(init) = &self.initialization {
            if init.current_epoch == epoch {
                Ok(*self
                    .current_epoch_participation
                    .get(validator_index as usize)
                    .ok_or(OpPoolError::RewardCacheOutOfBounds)?)
            } else if init.current_epoch == epoch + 1 {
                Ok(*self
                    .previous_epoch_participation
                    .get(validator_index as usize)
                    .ok_or(OpPoolError::RewardCacheOutOfBounds)?)
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

    fn update_previous_epoch_participation<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
    ) -> Result<(), BeaconStateError> {
        let default_participation = ParticipationFlags::default();
        self.previous_epoch_participation = state
            .previous_epoch_participation()?
            .iter()
            .map(|participation| *participation != default_participation)
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
            .map(|participation| *participation != default_participation)
            .collect();
        Ok(())
    }
}
