use crate::common::altair::BaseRewardPerIncrement;
use crate::common::base::SqrtTotalActiveBalance;
use crate::common::{altair, base};
use types::epoch_cache::{EpochCache, EpochCacheError, EpochCacheKey};
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256};

pub fn initialize_epoch_cache<E: EthSpec>(
    state: &BeaconState<E>,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<EpochCache, EpochCacheError> {
    let decision_block_root = state
        .proposer_shuffling_decision_root(Hash256::zero())
        .map_err(EpochCacheError::BeaconState)?;

    // The cache should never be constructed at slot 0 because it should only be used for
    // block processing (which implies slot > 0) or epoch processing (which implies slot >= 32).
    /* FIXME(sproul): EF tests like this
    if decision_block_root.is_zero() {
        return Err(EpochCacheError::InvalidSlot { slot: state.slot() });
    }
    */

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

    Ok(EpochCache::new(
        EpochCacheKey {
            epoch,
            decision_block_root,
        },
        base_rewards,
    ))
}
