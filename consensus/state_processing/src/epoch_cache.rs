use crate::common::{
    altair::{self, BaseRewardPerIncrement},
    base::{self, SqrtTotalActiveBalance},
};
use safe_arith::ArithError;
use std::sync::Arc;
use types::{BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, Hash256, Slot};

/// Cache of values which are uniquely determined at the start of an epoch.
///
/// The values are fixed with respect to the last block of the _prior_ epoch, which we refer
/// to as the "decision block". This cache is very similar to the `BeaconProposerCache` in that
/// beacon proposers are determined at exactly the same time as the values in this cache, so
/// the keys for the two caches are identical.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EpochCache {
    inner: Arc<Inner>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Inner {
    /// Unique identifier for this cache, which can be used to check its validity before use
    /// with any `BeaconState`.
    key: EpochCacheKey,
    /// Base reward for every validator in this epoch.
    base_rewards: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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
    pub fn new<E: EthSpec>(
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Self, EpochCacheError> {
        let epoch = state.current_epoch();
        let decision_block_root = state
            .proposer_shuffling_decision_root(Hash256::zero())
            .map_err(EpochCacheError::BeaconState)?;

        // The cache should never be constructed at slot 0 because it should only be used for
        // block processing (which implies slot > 0) or epoch processing (which implies slot >= 32).
        if decision_block_root.is_zero() {
            return Err(EpochCacheError::InvalidSlot { slot: state.slot() });
        }

        // Compute base rewards.
        let total_active_balance = state.get_total_active_balance()?;
        let sqrt_total_active_balance = SqrtTotalActiveBalance::new(total_active_balance);
        let base_reward_per_increment = BaseRewardPerIncrement::new(total_active_balance, spec)?;

        let mut base_rewards = Vec::with_capacity(state.validators().len());

        for validator in state.validators().iter() {
            let effective_balance = validator.effective_balance();

            let base_reward = if spec
                .altair_fork_epoch
                .map_or(false, |altair_epoch| epoch < altair_epoch)
            {
                base::get_base_reward(effective_balance, sqrt_total_active_balance, spec)?
            } else {
                altair::get_base_reward(effective_balance, base_reward_per_increment, spec)?
            };
            base_rewards.push(base_reward);
        }

        Ok(Self {
            inner: Arc::new(Inner {
                key: EpochCacheKey {
                    epoch,
                    decision_block_root,
                },
                base_rewards,
            }),
        })
    }

    pub fn check_validity<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> Result<(), EpochCacheError> {
        if self.inner.key.epoch != state.current_epoch() {
            return Err(EpochCacheError::IncorrectEpoch {
                cache: self.inner.key.epoch,
                state: state.current_epoch(),
            });
        }
        let state_decision_root = state
            .proposer_shuffling_decision_root(Hash256::zero())
            .map_err(EpochCacheError::BeaconState)?;
        if self.inner.key.decision_block_root != state_decision_root {
            return Err(EpochCacheError::IncorrectDecisionBlock {
                cache: self.inner.key.decision_block_root,
                state: state_decision_root,
            });
        }
        Ok(())
    }

    #[inline]
    pub fn get_base_reward(&self, validator_index: usize) -> Result<u64, EpochCacheError> {
        self.inner
            .base_rewards
            .get(validator_index)
            .copied()
            .ok_or(EpochCacheError::ValidatorIndexOutOfBounds { validator_index })
    }
}
