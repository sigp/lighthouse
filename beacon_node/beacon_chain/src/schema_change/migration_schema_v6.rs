///! These functions and structs are only relevant to the database migration from schema 5 to 6.
use crate::persisted_fork_choice::PersistedForkChoiceV1;
use crate::schema_change::types::{SszContainerV1, SszContainerV6};
use crate::BeaconChainTypes;
use ssz::four_byte_option_impl;
use ssz::{Decode, Encode};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);

pub(crate) fn update_execution_statuses<T: BeaconChainTypes>(
    persisted_fork_choice: &mut PersistedForkChoiceV1,
) -> Result<(), String> {
    let ssz_container_v1 =
        SszContainerV1::from_ssz_bytes(&persisted_fork_choice.fork_choice.proto_array_bytes)
            .map_err(|e| {
                format!(
                    "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
                    e
                )
            })?;

    let ssz_container_v6: SszContainerV6 = ssz_container_v1.into();

    persisted_fork_choice.fork_choice.proto_array_bytes = ssz_container_v6.as_ssz_bytes();
    Ok(())
}
