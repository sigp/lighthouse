use crate::common::altair::BaseRewardPerIncrement;
use crate::common::base::SqrtTotalActiveBalance;
use crate::common::{altair, base};
use types::epoch_cache::{EpochCache, EpochCacheError, EpochCacheKey};
use types::{ActivationQueue, BeaconState, ChainSpec, Epoch, EthSpec, Hash256};

/// Precursor to an `EpochCache`.
pub struct PreEpochCache {
    epoch_key: EpochCacheKey,
    effective_balances: Vec<u64>,
}

impl PreEpochCache {
    pub fn new_for_next_epoch<E: EthSpec>(state: &BeaconState<E>) -> Result<Self, EpochCacheError> {
        // The decision block root for the next epoch is the latest block root from this epoch.
        let latest_block_header = state.latest_block_header();

        // State root should already have been filled in by `process_slot`.
        // FIXME(sproul): proper error
        assert!(!latest_block_header.state_root().is_zero());

        let decision_block_root = latest_block_header.canonical_root();

        let epoch_key = EpochCacheKey {
            epoch: state.next_epoch()?,
            decision_block_root,
        };

        Ok(Self {
            epoch_key,
            effective_balances: Vec::with_capacity(state.validators().len()),
        })
    }

    pub fn push_effective_balance(&mut self, effective_balance: u64) {
        self.effective_balances.push(effective_balance);
    }

    pub fn into_epoch_cache(
        self,
        total_active_balance: u64,
        activation_queue: ActivationQueue,
        spec: &ChainSpec,
    ) -> Result<EpochCache, EpochCacheError> {
        let epoch = self.epoch_key.epoch;
        let sqrt_total_active_balance = SqrtTotalActiveBalance::new(total_active_balance);
        let base_reward_per_increment = BaseRewardPerIncrement::new(total_active_balance, spec)?;

        let mut base_rewards = Vec::with_capacity(self.effective_balances.len());

        // This is another O(n) iteration, but it's over a Vec, and is only necessary because we
        // want access to the base rewards in block processing.
        for effective_balance in self.effective_balances {
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

        Ok(EpochCache::new(
            self.epoch_key,
            base_rewards,
            activation_queue,
        ))
    }
}

pub fn initialize_epoch_cache<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), EpochCacheError> {
    let epoch = state.current_epoch();
    let epoch_cache: &EpochCache = state.epoch_cache();
    let decision_block_root = state
        .proposer_shuffling_decision_root(Hash256::zero())
        .map_err(EpochCacheError::BeaconState)?;

    if epoch_cache
        .check_validity::<E>(epoch, decision_block_root)
        .is_ok()
    {
        // `EpochCache` has already been initialized and is valid, no need to initialize.
        return Ok(());
    }

    // Compute base rewards.
    state.build_total_active_balance_cache_at(epoch, spec)?;
    let total_active_balance = state.get_total_active_balance_at_epoch(epoch)?;
    let sqrt_total_active_balance = SqrtTotalActiveBalance::new(total_active_balance);
    let base_reward_per_increment = BaseRewardPerIncrement::new(total_active_balance, spec)?;

    let mut base_rewards = Vec::with_capacity(state.validators().len());

    // Compute activation queue.
    let mut activation_queue = ActivationQueue::default();

    for (index, validator) in state.validators().iter().enumerate() {
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

        // Add to speculative activation queue.
        activation_queue.add_if_could_be_eligible_for_activation(index, validator, epoch, spec);
    }

    *state.epoch_cache_mut() = EpochCache::new(
        EpochCacheKey {
            epoch,
            decision_block_root,
        },
        base_rewards,
        activation_queue,
    );

    Ok(())
}
