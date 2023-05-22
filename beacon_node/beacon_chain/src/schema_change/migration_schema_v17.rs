use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY};
use crate::persisted_fork_choice::{PersistedForkChoiceV11, PersistedForkChoiceV17};
use proto_array::core::{SszContainerV16, SszContainerV17};
use slog::{debug, Logger};
use ssz::{Decode, Encode};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

pub fn upgrade_fork_choice(
    mut fork_choice: PersistedForkChoiceV11,
) -> Result<PersistedForkChoiceV17, Error> {
    let ssz_container_v16 = SszContainerV16::from_ssz_bytes(
        &fork_choice.fork_choice.proto_array_bytes,
    )
    .map_err(|e| {
        Error::SchemaMigrationError(format!(
            "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
            e
        ))
    })?;

    let ssz_container_v17: SszContainerV17 = ssz_container_v16.try_into().map_err(|e| {
        Error::SchemaMigrationError(format!(
            "Missing checkpoint during schema migration: {:?}",
            e
        ))
    })?;
    fork_choice.fork_choice.proto_array_bytes = ssz_container_v17.as_ssz_bytes();

    Ok(fork_choice.into())
}

pub fn downgrade_fork_choice(
    mut fork_choice: PersistedForkChoiceV17,
) -> Result<PersistedForkChoiceV11, Error> {
    let ssz_container_v17 = SszContainerV17::from_ssz_bytes(
        &fork_choice.fork_choice.proto_array_bytes,
    )
    .map_err(|e| {
        Error::SchemaMigrationError(format!(
            "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
            e
        ))
    })?;

    let ssz_container_v16: SszContainerV16 = ssz_container_v17.into();
    fork_choice.fork_choice.proto_array_bytes = ssz_container_v16.as_ssz_bytes();

    Ok(fork_choice.into())
}

pub fn upgrade_to_v17<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Get persisted_fork_choice.
    let v11 = db
        .get_item::<PersistedForkChoiceV11>(&FORK_CHOICE_DB_KEY)?
        .ok_or_else(|| Error::SchemaMigrationError("fork choice missing from database".into()))?;

    let v17 = upgrade_fork_choice(v11)?;

    debug!(
        log,
        "Removing unused best_justified_checkpoint from fork choice store."
    );

    Ok(vec![v17.as_kv_store_op(FORK_CHOICE_DB_KEY)])
}

pub fn downgrade_from_v17<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Get persisted_fork_choice.
    let v17 = db
        .get_item::<PersistedForkChoiceV17>(&FORK_CHOICE_DB_KEY)?
        .ok_or_else(|| Error::SchemaMigrationError("fork choice missing from database".into()))?;

    let v11 = downgrade_fork_choice(v17)?;

    debug!(
        log,
        "Adding junk best_justified_checkpoint to fork choice store."
    );

    Ok(vec![v11.as_kv_store_op(FORK_CHOICE_DB_KEY)])
}
