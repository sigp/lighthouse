use crate::{BeaconState, BeaconStateError, Epoch, EthSpec, Hash256, Slot};
use safe_arith::ArithError;
use std::sync::Arc;

/// Cache of values which are uniquely determined at the start of an epoch.
///
/// The values are fixed with respect to the last block of the _prior_ epoch, which we refer
/// to as the "decision block". This cache is very similar to the `BeaconProposerCache` in that
/// beacon proposers are determined at exactly the same time as the values in this cache, so
/// the keys for the two caches are identical.
#[derive(Debug, PartialEq, Eq, Clone, Default, arbitrary::Arbitrary)]
pub struct EpochCache {
    inner: Option<Arc<Inner>>,
}

#[derive(Debug, PartialEq, Eq, Clone, arbitrary::Arbitrary)]
struct Inner {
    /// Unique identifier for this cache, which can be used to check its validity before use
    /// with any `BeaconState`.
    key: EpochCacheKey,
    /// Base reward for every validator in this epoch.
    base_rewards: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, arbitrary::Arbitrary)]
pub struct EpochCacheKey {
    pub epoch: Epoch,
    pub decision_block_root: Hash256,
}

#[derive(Debug, PartialEq, Clone)]
pub enum EpochCacheError {
    IncorrectEpoch { cache: Epoch, state: Epoch },
    IncorrectDecisionBlock { cache: Hash256, state: Hash256 },
    ValidatorIndexOutOfBounds { validator_index: usize },
    InvalidSlot { slot: Slot },
    Arith(ArithError),
    BeaconState(BeaconStateError),
    CacheNotInitialized,
}

impl From<BeaconStateError> for EpochCacheError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl From<ArithError> for EpochCacheError {
    fn from(e: ArithError) -> Self {
        Self::Arith(e)
    }
}

impl EpochCache {
    pub fn new(key: EpochCacheKey, base_rewards: Vec<u64>) -> EpochCache {
        Self {
            inner: Some(Arc::new(Inner { key, base_rewards })),
        }
    }

    pub fn check_validity<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> Result<(), EpochCacheError> {
        let cache = self
            .inner
            .as_ref()
            .ok_or(EpochCacheError::CacheNotInitialized)?;
        if cache.key.epoch != state.current_epoch() {
            return Err(EpochCacheError::IncorrectEpoch {
                cache: cache.key.epoch,
                state: state.current_epoch(),
            });
        }
        let state_decision_root = state
            .proposer_shuffling_decision_root(Hash256::zero())
            .map_err(EpochCacheError::BeaconState)?;
        if cache.key.decision_block_root != state_decision_root {
            return Err(EpochCacheError::IncorrectDecisionBlock {
                cache: cache.key.decision_block_root,
                state: state_decision_root,
            });
        }
        Ok(())
    }

    #[inline]
    pub fn get_base_reward(&self, validator_index: usize) -> Result<u64, EpochCacheError> {
        self.inner
            .as_ref()
            .ok_or(EpochCacheError::CacheNotInitialized)?
            .base_rewards
            .get(validator_index)
            .copied()
            .ok_or(EpochCacheError::ValidatorIndexOutOfBounds { validator_index })
    }
}
