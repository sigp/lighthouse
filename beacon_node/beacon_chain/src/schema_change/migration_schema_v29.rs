use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY};
use crate::persisted_fork_choice::{PersistedForkChoiceV28, PersistedForkChoiceV29};
use std::collections::HashMap;
use store::hot_cold_store::HotColdDB;
use store::{DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};
use tracing::warn;
use types::EthSpec;

/// Upgrade from schema v28 to v29.
///
/// - Clears `best_child` and `best_descendant` on all nodes (replaced by
///   virtual tree walk).
/// - Fails if the persisted fork choice contains any V17 (pre-Gloas) proto
///   nodes at or after the Gloas fork slot.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn upgrade_to_v29<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let gloas_fork_slot = db
        .spec
        .gloas_fork_epoch
        .map(|epoch| epoch.start_slot(T::EthSpec::slots_per_epoch()));

    // Load the persisted fork choice (v28 format).
    let Some(fc_bytes) = db
        .hot_db
        .get_bytes(DBColumn::ForkChoice, FORK_CHOICE_DB_KEY.as_slice())?
    else {
        return Ok(vec![]);
    };

    let persisted_v28 = PersistedForkChoiceV28::from_bytes(&fc_bytes, db.get_config())?;

    // Check for V17 nodes at/after the Gloas fork slot.
    if let Some(gloas_fork_slot) = gloas_fork_slot {
        let bad_node = persisted_v28
            .fork_choice_v28
            .proto_array_v28
            .nodes
            .iter()
            .find(|node| node.slot >= gloas_fork_slot);

        if let Some(node) = bad_node {
            return Err(StoreError::MigrationError(format!(
                "cannot upgrade from v28 to v29: found V17 proto node at slot {} (root: {:?}) \
                 which is at or after the Gloas fork slot {}. This node has synced a chain with \
                 Gloas disabled and cannot be upgraded. Please resync from scratch.",
                node.slot, node.root, gloas_fork_slot,
            )));
        }
    }

    // Read the previous proposer boost before converting to V29 (V29 no longer stores it).
    let previous_proposer_boost = persisted_v28
        .fork_choice_v28
        .proto_array_v28
        .previous_proposer_boost;

    // Convert to v29.
    let mut persisted_v29 = PersistedForkChoiceV29::from(persisted_v28);

    // Subtract the proposer boost from the boosted node and all its ancestors.
    //
    // In the V28 schema, `apply_score_changes` baked the proposer boost directly into node
    // weights and back-propagated it up the parent chain. In V29, the boost is computed
    // on-the-fly during the virtual tree walk. If we don't subtract the baked-in boost here,
    // it will be double-counted after the upgrade.
    if !previous_proposer_boost.root.is_zero() && previous_proposer_boost.score > 0 {
        let score = previous_proposer_boost.score;
        let indices: HashMap<_, _> = persisted_v29
            .fork_choice
            .proto_array
            .indices
            .iter()
            .cloned()
            .collect();

        if let Some(node_index) = indices.get(&previous_proposer_boost.root).copied() {
            let nodes = &mut persisted_v29.fork_choice.proto_array.nodes;
            let mut current = Some(node_index);
            while let Some(idx) = current {
                if let Some(node) = nodes.get_mut(idx) {
                    *node.weight_mut() = node.weight().saturating_sub(score);
                    current = node.parent();
                } else {
                    break;
                }
            }
        } else {
            warn!(
                root = ?previous_proposer_boost.root,
                "Proposer boost node missing from fork choice"
            );
        }
    }

    Ok(vec![
        persisted_v29.as_kv_store_op(FORK_CHOICE_DB_KEY, db.get_config())?,
    ])
}

/// Downgrade from schema v29 to v28.
///
/// Converts the persisted fork choice from V29 format back to V28.
/// Fails if the persisted fork choice contains any V29 proto nodes, as these contain
/// payload-specific fields that cannot be losslessly converted back to V17 format.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn downgrade_from_v29<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    // Load the persisted fork choice (v29 format, compressed).
    let Some(fc_bytes) = db
        .hot_db
        .get_bytes(DBColumn::ForkChoice, FORK_CHOICE_DB_KEY.as_slice())?
    else {
        return Ok(vec![]);
    };

    let persisted_v29 =
        PersistedForkChoiceV29::from_bytes(&fc_bytes, db.get_config()).map_err(|e| {
            StoreError::MigrationError(format!(
                "cannot downgrade from v29 to v28: failed to decode fork choice: {:?}",
                e
            ))
        })?;

    let has_v29_node = persisted_v29
        .fork_choice
        .proto_array
        .nodes
        .iter()
        .any(|node| matches!(node, proto_array::core::ProtoNode::V29(_)));

    if has_v29_node {
        return Err(StoreError::MigrationError(
            "cannot downgrade from v29 to v28: the persisted fork choice contains V29 proto \
             nodes which cannot be losslessly converted to V17 format. The Gloas-specific \
             payload data would be lost."
                .to_string(),
        ));
    }

    // Convert to v28 and encode.
    let persisted_v28 = PersistedForkChoiceV28::from(persisted_v29);

    Ok(vec![
        persisted_v28.as_kv_store_op(FORK_CHOICE_DB_KEY, db.get_config())?,
    ])
}
