use crate::{EpochCache, EpochCacheError};
use std::borrow::Cow;
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{
    BeaconState, BeaconStateError, ChainSpec, EthSpec, ExecPayload, Hash256, SignedBeaconBlock,
    Slot,
};

#[derive(Debug, Clone)]
pub struct ConsensusContext<T: EthSpec> {
    /// Slot to act as an identifier/safeguard
    slot: Slot,
    /// Proposer index of the block at `slot`.
    proposer_index: Option<u64>,
    /// Block root of the block at `slot`.
    current_block_root: Option<Hash256>,
    /// Epoch cache of values that are useful for block processing that are static over an epoch.
    epoch_cache: Option<EpochCache>,
    _phantom: PhantomData<T>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ContextError {
    BeaconState(BeaconStateError),
    EpochCache(EpochCacheError),
    SlotMismatch { slot: Slot, expected: Slot },
}

impl From<BeaconStateError> for ContextError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl From<EpochCacheError> for ContextError {
    fn from(e: EpochCacheError) -> Self {
        Self::EpochCache(e)
    }
}

impl<T: EthSpec> ConsensusContext<T> {
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            proposer_index: None,
            current_block_root: None,
            epoch_cache: None,
            _phantom: PhantomData,
        }
    }

    pub fn set_proposer_index(mut self, proposer_index: u64) -> Self {
        self.proposer_index = Some(proposer_index);
        self
    }

    pub fn get_proposer_index(
        &mut self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<u64, ContextError> {
        self.check_slot(state.slot())?;

        if let Some(proposer_index) = self.proposer_index {
            return Ok(proposer_index);
        }

        let proposer_index = state.get_beacon_proposer_index(self.slot, spec)? as u64;
        self.proposer_index = Some(proposer_index);
        Ok(proposer_index)
    }

    pub fn set_current_block_root(mut self, block_root: Hash256) -> Self {
        self.current_block_root = Some(block_root);
        self
    }

    pub fn get_current_block_root<Payload: ExecPayload<T>>(
        &mut self,
        block: &SignedBeaconBlock<T, Payload>,
    ) -> Result<Hash256, ContextError> {
        self.check_slot(block.slot())?;

        if let Some(current_block_root) = self.current_block_root {
            return Ok(current_block_root);
        }

        let current_block_root = block.message().tree_hash_root();
        self.current_block_root = Some(current_block_root);
        Ok(current_block_root)
    }

    fn check_slot(&self, slot: Slot) -> Result<(), ContextError> {
        if slot == self.slot {
            Ok(())
        } else {
            Err(ContextError::SlotMismatch {
                slot,
                expected: self.slot,
            })
        }
    }

    pub fn set_epoch_cache(mut self, epoch_cache: EpochCache) -> Self {
        self.epoch_cache = Some(epoch_cache);
        self
    }

    pub fn get_base_reward<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<u64, ContextError> {
        self.check_slot(state.slot())?;

        // Build epoch cache if not already built.
        let epoch_cache = if let Some(ref cache) = self.epoch_cache {
            Cow::Borrowed(cache)
        } else {
            let cache = EpochCache::new(state, spec)?;
            self.epoch_cache = Some(cache.clone());
            Cow::Owned(cache)
        };

        Ok(epoch_cache.get_base_reward(validator_index)?)
    }
}
