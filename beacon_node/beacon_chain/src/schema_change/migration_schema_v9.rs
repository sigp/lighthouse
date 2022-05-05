use crate::persisted_fork_choice::PersistedForkChoiceV8;
use crate::schema_change::{
    types::{SszContainerV7, SszContainerV9},
    StoreError,
};
use proto_array::core::SszContainer;
use ssz::{Decode, Encode};

pub fn update_fork_choice(
    mut fork_choice: PersistedForkChoiceV8,
) -> Result<PersistedForkChoiceV8, StoreError> {
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
    let ssz_container_v9: SszContainerV9 = ssz_container_v7.into();
    let ssz_container: SszContainer = ssz_container_v9.into();

    fork_choice.fork_choice.proto_array_bytes = ssz_container.as_ssz_bytes();

    Ok(fork_choice)
}
