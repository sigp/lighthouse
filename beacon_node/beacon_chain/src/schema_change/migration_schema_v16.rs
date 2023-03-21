use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY};
use crate::persisted_fork_choice::PersistedForkChoiceV11;
use slog::{debug, Logger};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

pub fn upgrade_to_v16<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    drop_balances_cache::<T>(db, log)
}

pub fn downgrade_from_v16<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    drop_balances_cache::<T>(db, log)
}

/// Drop the balances cache from the fork choice store.
///
/// There aren't any type-level changes in this schema migration, however the
/// way that we compute the `JustifiedBalances` has changed due to:
/// https://github.com/sigp/lighthouse/pull/3962
pub fn drop_balances_cache<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let mut persisted_fork_choice = db
        .get_item::<PersistedForkChoiceV11>(&FORK_CHOICE_DB_KEY)?
        .ok_or_else(|| Error::SchemaMigrationError("fork choice missing from database".into()))?;

    debug!(
        log,
        "Dropping fork choice balances cache";
        "item_count" => persisted_fork_choice.fork_choice_store.balances_cache.items.len()
    );

    // Drop all items in the balances cache.
    persisted_fork_choice.fork_choice_store.balances_cache = <_>::default();

    let kv_op = persisted_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY);

    Ok(vec![kv_op])
}
