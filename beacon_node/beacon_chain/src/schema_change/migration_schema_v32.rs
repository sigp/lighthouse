use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY};
use crate::persisted_fork_choice::PersistedForkChoiceV29;
use proto_array::core::{ProtoNode, ProtoNodeV29, ProtoNodeV32};
use store::hot_cold_store::HotColdDB;
use store::{DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};

/// Upgrade from schema v31 to v32.
///
/// Converts V29 proto nodes to V32. V29 nodes have no inclusion list verdict, so their payloads
/// are recorded as satisfying the inclusion lists.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn upgrade_to_v32<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    rewrite_proto_nodes::<T>(db, "upgrade from v31 to v32", |node| match node {
        ProtoNode::V29(v29) => ProtoNode::V32(upgrade_node(v29)),
        node => node,
    })
}

/// Downgrade from schema v32 to v31.
///
/// Converts V32 proto nodes back to V29, dropping the inclusion list verdict.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn downgrade_from_v32<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    rewrite_proto_nodes::<T>(db, "downgrade from v32 to v31", |node| match node {
        ProtoNode::V32(v32) => ProtoNode::V29(downgrade_node(v32)),
        node => node,
    })
}

fn rewrite_proto_nodes<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    migration: &str,
    convert: impl Fn(ProtoNode) -> ProtoNode,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let Some(fc_bytes) = db
        .hot_db
        .get_bytes(DBColumn::ForkChoice, FORK_CHOICE_DB_KEY.as_slice())?
    else {
        return Ok(vec![]);
    };

    let mut persisted =
        PersistedForkChoiceV29::from_bytes(&fc_bytes, db.get_config()).map_err(|e| {
            StoreError::MigrationError(format!(
                "cannot {migration}: failed to decode fork choice: {e:?}"
            ))
        })?;

    let nodes = &mut persisted.fork_choice.proto_array.nodes;
    *nodes = std::mem::take(nodes).into_iter().map(convert).collect();

    Ok(vec![
        persisted.as_kv_store_op(FORK_CHOICE_DB_KEY, db.get_config())?,
    ])
}

fn upgrade_node(v29: ProtoNodeV29) -> ProtoNodeV32 {
    ProtoNodeV32 {
        slot: v29.slot,
        state_root: v29.state_root,
        target_root: v29.target_root,
        current_epoch_shuffling_id: v29.current_epoch_shuffling_id,
        next_epoch_shuffling_id: v29.next_epoch_shuffling_id,
        root: v29.root,
        parent: v29.parent,
        justified_checkpoint: v29.justified_checkpoint,
        finalized_checkpoint: v29.finalized_checkpoint,
        weight: v29.weight,
        execution_status: v29.execution_status,
        unrealized_justified_checkpoint: v29.unrealized_justified_checkpoint,
        unrealized_finalized_checkpoint: v29.unrealized_finalized_checkpoint,
        parent_payload_status: v29.parent_payload_status,
        empty_payload_weight: v29.empty_payload_weight,
        full_payload_weight: v29.full_payload_weight,
        execution_payload_block_hash: v29.execution_payload_block_hash,
        execution_payload_parent_hash: v29.execution_payload_parent_hash,
        block_timeliness_attestation_threshold: v29.block_timeliness_attestation_threshold,
        block_timeliness_ptc_threshold: v29.block_timeliness_ptc_threshold,
        payload_timeliness_votes: v29.payload_timeliness_votes,
        payload_data_availability_votes: v29.payload_data_availability_votes,
        ptc_participation: v29.ptc_participation,
        payload_received: v29.payload_received,
        payload_inclusion_list_satisfied: true,
        proposer_index: v29.proposer_index,
        equivocating_attestation_score: v29.equivocating_attestation_score,
    }
}

fn downgrade_node(v32: ProtoNodeV32) -> ProtoNodeV29 {
    ProtoNodeV29 {
        slot: v32.slot,
        state_root: v32.state_root,
        target_root: v32.target_root,
        current_epoch_shuffling_id: v32.current_epoch_shuffling_id,
        next_epoch_shuffling_id: v32.next_epoch_shuffling_id,
        root: v32.root,
        parent: v32.parent,
        justified_checkpoint: v32.justified_checkpoint,
        finalized_checkpoint: v32.finalized_checkpoint,
        weight: v32.weight,
        execution_status: v32.execution_status,
        unrealized_justified_checkpoint: v32.unrealized_justified_checkpoint,
        unrealized_finalized_checkpoint: v32.unrealized_finalized_checkpoint,
        parent_payload_status: v32.parent_payload_status,
        empty_payload_weight: v32.empty_payload_weight,
        full_payload_weight: v32.full_payload_weight,
        execution_payload_block_hash: v32.execution_payload_block_hash,
        execution_payload_parent_hash: v32.execution_payload_parent_hash,
        block_timeliness_attestation_threshold: v32.block_timeliness_attestation_threshold,
        block_timeliness_ptc_threshold: v32.block_timeliness_ptc_threshold,
        payload_timeliness_votes: v32.payload_timeliness_votes,
        payload_data_availability_votes: v32.payload_data_availability_votes,
        ptc_participation: v32.ptc_participation,
        payload_received: v32.payload_received,
        proposer_index: v32.proposer_index,
        equivocating_attestation_score: v32.equivocating_attestation_score,
    }
}
