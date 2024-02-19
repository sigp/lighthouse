use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY};
use crate::persisted_fork_choice::{PersistedForkChoiceV17, PersistedForkChoiceV20};
use slog::{debug, Logger};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

pub fn upgrade_to_v20<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let v17 = db
        .get_item::<PersistedForkChoiceV17>(&FORK_CHOICE_DB_KEY)?
        .ok_or_else(|| Error::SchemaMigrationError("fork choice missing from database".into()))?;

    let v20: PersistedForkChoiceV20 = v17.into();

    debug!(log, "Adding anchor_state to fork choice");

    Ok(vec![v20.as_kv_store_op(FORK_CHOICE_DB_KEY)])
}

pub fn downgrade_from_v20<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let v20 = db
        .get_item::<PersistedForkChoiceV20>(&FORK_CHOICE_DB_KEY)?
        .ok_or_else(|| Error::SchemaMigrationError("fork choice missing from database".into()))?;

    let v17: PersistedForkChoiceV17 = v20.into();

    debug!(log, "Dropping anchor_state from fork choice.");

    Ok(vec![v17.as_kv_store_op(FORK_CHOICE_DB_KEY)])
}
