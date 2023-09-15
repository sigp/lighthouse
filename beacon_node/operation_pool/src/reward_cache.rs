use crate::OpPoolError;
use bitvec::vec::BitVec;
use types::{BeaconState, BeaconStateError, Epoch, EthSpec, Hash256, ParticipationFlags};

#[derive(Debug, PartialEq, Eq, Clone)]
struct Initialization {
    current_epoch: Epoch,
    latest_block_root: Hash256,
}

/// Cache to store pre-computed information for block proposal.
#[derive(Debug, Clone, Default)]
pub struct RewardCache {
    initialization: Option<Initialization>,
    /// `BitVec` of validator indices which don't have default participation flags for the prev epoch.
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

    /// Return the root of the latest block applied to `state`.
    ///
    /// For simplicity at genesis we return the zero hash, which will cause one unnecessary
    /// re-calculation in `update`.
    fn latest_block_root<E: EthSpec>(state: &BeaconState<E>) -> Result<Hash256, OpPoolError> {
        if state.slot() == 0 {
            Ok(Hash256::zero())
        } else {
            Ok(*state
                .get_block_root(state.slot() - 1)
                .map_err(OpPoolError::RewardCacheGetBlockRoot)?)
        }
    }

    /// Update the cache.
    pub fn update<E: EthSpec>(&mut self, state: &BeaconState<E>) -> Result<(), OpPoolError> {
        if matches!(state, BeaconState::Base(_)) {
            return Ok(());
        }

        let current_epoch = state.current_epoch();
        let latest_block_root = Self::latest_block_root(state)?;

        let new_init = Initialization {
            current_epoch,
            latest_block_root,
        };

        // The participation flags change every block, and will almost always need updating when
        // this function is called at a new slot.
        if self
            .initialization
            .as_ref()
            .map_or(true, |init| *init != new_init)
        {
            self.update_previous_epoch_participation(state)
                .map_err(OpPoolError::RewardCacheUpdatePrevEpoch)?;
            self.update_current_epoch_participation(state)
                .map_err(OpPoolError::RewardCacheUpdateCurrEpoch)?;

            self.initialization = Some(new_init);
        }

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
