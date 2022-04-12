use crate::beacon_chain::BeaconChainTypes;
use crate::beacon_fork_choice_store::{
    BalancesCacheV8, CacheItemV8, PersistedForkChoiceStoreV7, PersistedForkChoiceStoreV8,
};
use crate::persisted_fork_choice::{PersistedForkChoiceV7, PersistedForkChoiceV8};
use std::sync::Arc;
use store::{Error as StoreError, HotColdDB};
use types::EthSpec;

pub fn update_fork_choice<T: BeaconChainTypes>(
    fork_choice: PersistedForkChoiceV7,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<PersistedForkChoiceV8, StoreError> {
    let PersistedForkChoiceStoreV7 {
        balances_cache,
        time,
        finalized_checkpoint,
        justified_checkpoint,
        justified_balances,
        best_justified_checkpoint,
        proposer_boost_root,
    } = fork_choice.fork_choice_store;
    let mut fork_choice_store = PersistedForkChoiceStoreV8 {
        balances_cache: BalancesCacheV8::default(),
        time,
        finalized_checkpoint,
        justified_checkpoint,
        justified_balances,
        best_justified_checkpoint,
        proposer_boost_root,
    };

    // Add epochs to the balances cache. It's safe to just use the block's epoch because
    // before schema v8 the cache would always miss on skipped slots.
    for item in balances_cache.items {
        // Drop any blocks that aren't found, they're presumably too old and this is only a cache.
        if let Some(block) = db.get_full_block_prior_to_v9(&item.block_root)? {
            fork_choice_store.balances_cache.items.push(CacheItemV8 {
                block_root: item.block_root,
                epoch: block.slot().epoch(T::EthSpec::slots_per_epoch()),
                balances: item.balances,
            });
        }
    }

    Ok(PersistedForkChoiceV8 {
        fork_choice: fork_choice.fork_choice,
        fork_choice_store,
    })
}
