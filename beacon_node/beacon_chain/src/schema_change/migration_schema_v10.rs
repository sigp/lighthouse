use crate::beacon_fork_choice_store::{PersistedForkChoiceStoreV10, PersistedForkChoiceStoreV8};
use crate::persisted_fork_choice::{PersistedForkChoiceV10, PersistedForkChoiceV8};
use crate::schema_change::{
    types::{SszContainerV10, SszContainerV7},
    StoreError,
};
use proto_array::core::SszContainer;
use ssz::{Decode, Encode};

pub fn update_fork_choice(
    mut fork_choice: PersistedForkChoiceV8,
) -> Result<PersistedForkChoiceV10, StoreError> {
    let ssz_container_v7 = SszContainerV7::from_ssz_bytes(
        &fork_choice.fork_choice.proto_array_bytes,
    )
    .map_err(|e| {
        StoreError::SchemaMigrationError(format!(
            "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
            e
        ))
    })?;

    // These transformations instantiate `node.unrealized_justified_checkpoint` and
    // `node.unrealized_finalized_checkpoint` to `None`.
    let ssz_container_v10: SszContainerV10 = ssz_container_v7.into();
    let ssz_container: SszContainer = ssz_container_v10.into();
    fork_choice.fork_choice.proto_array_bytes = ssz_container.as_ssz_bytes();

    Ok(fork_choice.into())
}

pub fn downgrade_fork_choice(
    mut fork_choice: PersistedForkChoiceV10,
) -> Result<PersistedForkChoiceV8, StoreError> {
    let ssz_container_v10 = SszContainerV10::from_ssz_bytes(
        &fork_choice.fork_choice.proto_array_bytes,
    )
    .map_err(|e| {
        StoreError::SchemaMigrationError(format!(
            "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
            e
        ))
    })?;

    let ssz_container_v7: SszContainerV7 = ssz_container_v10.into();
    fork_choice.fork_choice.proto_array_bytes = ssz_container_v7.as_ssz_bytes();

    Ok(fork_choice.into())
}

impl From<PersistedForkChoiceStoreV8> for PersistedForkChoiceStoreV10 {
    fn from(other: PersistedForkChoiceStoreV8) -> Self {
        Self {
            balances_cache: other.balances_cache,
            time: other.time,
            finalized_checkpoint: other.finalized_checkpoint,
            justified_checkpoint: other.justified_checkpoint,
            justified_balances: other.justified_balances,
            best_justified_checkpoint: other.best_justified_checkpoint,
            unrealized_justified_checkpoint: other.best_justified_checkpoint,
            unrealized_finalized_checkpoint: other.finalized_checkpoint,
            proposer_boost_root: other.proposer_boost_root,
        }
    }
}

impl From<PersistedForkChoiceV8> for PersistedForkChoiceV10 {
    fn from(other: PersistedForkChoiceV8) -> Self {
        Self {
            fork_choice: other.fork_choice,
            fork_choice_store: other.fork_choice_store.into(),
        }
    }
}

impl From<PersistedForkChoiceStoreV10> for PersistedForkChoiceStoreV8 {
    fn from(other: PersistedForkChoiceStoreV10) -> Self {
        Self {
            balances_cache: other.balances_cache,
            time: other.time,
            finalized_checkpoint: other.finalized_checkpoint,
            justified_checkpoint: other.justified_checkpoint,
            justified_balances: other.justified_balances,
            best_justified_checkpoint: other.best_justified_checkpoint,
            proposer_boost_root: other.proposer_boost_root,
        }
    }
}

impl From<PersistedForkChoiceV10> for PersistedForkChoiceV8 {
    fn from(other: PersistedForkChoiceV10) -> Self {
        Self {
            fork_choice: other.fork_choice,
            fork_choice_store: other.fork_choice_store.into(),
        }
    }
}
