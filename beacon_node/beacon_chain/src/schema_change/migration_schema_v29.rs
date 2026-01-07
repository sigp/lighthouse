use crate::BeaconChainTypes;
use crate::beacon_chain::FORK_CHOICE_DB_KEY;
use crate::persisted_fork_choice::{PersistedForkChoiceV28, PersistedForkChoiceV29};
use std::sync::Arc;
use store::{DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp};

/// Upgrade fork-choice store to v29.
pub fn upgrade_to_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let persisted_fork_choice_v28 = PersistedForkChoiceV28::from_bytes(
        &db.hot_db
            .get_bytes(DBColumn::ForkChoice, FORK_CHOICE_DB_KEY.as_slice())?
            .ok_or(
                // Fork choice should exist if the database exists.
                Error::MigrationError("No fork choice found in DB".to_string()),
            )?,
        db.get_config(),
    )?;

    // Set local_irreversible_checkpoint = finalized_checkpoint
    let persisted_fork_choice_v29: PersistedForkChoiceV29 = persisted_fork_choice_v28.into();

    Ok(vec![KeyValueStoreOp::PutKeyValue(
        DBColumn::ForkChoice,
        FORK_CHOICE_DB_KEY.to_vec(),
        persisted_fork_choice_v29.as_bytes(db.get_config())?,
    )])
}

pub fn downgrade_from_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let persisted_fork_choice_v29 = PersistedForkChoiceV29::from_bytes(
        &db.hot_db
            .get_bytes(DBColumn::ForkChoice, FORK_CHOICE_DB_KEY.as_slice())?
            .ok_or(
                // Fork choice should exist if the database exists.
                Error::MigrationError("No fork choice found in DB".to_string()),
            )?,
        db.get_config(),
    )?;

    // Drop local_irreversible_checkpoint property
    let persisted_fork_choice_v28: PersistedForkChoiceV28 = persisted_fork_choice_v29.into();

    Ok(vec![KeyValueStoreOp::PutKeyValue(
        DBColumn::ForkChoice,
        FORK_CHOICE_DB_KEY.to_vec(),
        persisted_fork_choice_v28.as_bytes(db.get_config())?,
    )])
}
