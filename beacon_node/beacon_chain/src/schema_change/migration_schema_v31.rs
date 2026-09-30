use crate::beacon_chain::BeaconChainTypes;
use ssz::{Decode, Encode};
use store::hot_cold_store::HotColdDB;
use store::{DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};
use types::{Hash256, SignedExecutionPayloadEnvelope, SignedExecutionPayloadEnvelopeSummary};

/// Upgrade from schema v30 to v31.
///
/// Splits each signed execution payload envelope in `PayloadEnvelope` into its persistent summary
/// and prunable execution payload. When payload pruning is enabled, bodies before the split are
/// removed during migration because regular pruning will not revisit them.
pub fn upgrade_to_v31<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let mut ops = vec![];
    let split_slot = db.get_split_slot();
    let prune_payloads = db.get_config().prune_payloads;

    for result in db.hot_db.iter_column::<Hash256>(DBColumn::PayloadBody) {
        let (block_root, envelope_bytes) = result?;
        let envelope = SignedExecutionPayloadEnvelope::<T::EthSpec>::from_ssz_bytes(
            &envelope_bytes,
        )
        .map_err(|error| {
            StoreError::MigrationError(format!(
                "cannot upgrade from v30 to v31: invalid payload envelope at {block_root:?}: \
                 {error:?}"
            ))
        })?;

        // Older Gloas databases may retain envelopes for blocks that finalized as EMPTY.
        // Their summaries must not survive the upgrade, regardless of payload-pruning mode.
        if finalized_as_empty::<T>(db, block_root, &envelope)? {
            ops.push(KeyValueStoreOp::DeleteKey(
                DBColumn::PayloadBody,
                block_root.as_slice().to_vec(),
            ));
            continue;
        }

        let summary = SignedExecutionPayloadEnvelopeSummary::from(&envelope);

        if prune_payloads && envelope.slot() < split_slot {
            // The old full envelope occupies the same key as the new body, so it must be deleted.
            ops.push(KeyValueStoreOp::DeleteKey(
                DBColumn::PayloadBody,
                block_root.as_slice().to_vec(),
            ));
        } else {
            let payload = &envelope.message.payload;
            ops.push(KeyValueStoreOp::PutKeyValue(
                DBColumn::PayloadBody,
                block_root.as_slice().to_vec(),
                // Match `ExecutionPayloadBody` without cloning its variable-length fields.
                (
                    &payload.transactions,
                    &payload.withdrawals,
                    &payload.block_access_list,
                )
                    .as_ssz_bytes(),
            ));
        }
        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::PayloadSummary,
            block_root.as_slice().to_vec(),
            summary.as_ssz_bytes(),
        ));
    }

    Ok(ops)
}

/// Use the next canonical block to determine the status of a payload before the split.
/// The freezer has a root for each slot before the split, including skipped slots. If that
/// history has not been backfilled yet, retain the envelope rather than guessing its status.
fn finalized_as_empty<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    block_root: Hash256,
    envelope: &SignedExecutionPayloadEnvelope<T::EthSpec>,
) -> Result<bool, StoreError> {
    let split = db.get_split_info();
    if envelope.slot() >= split.slot || block_root == split.block_root {
        return Ok(false);
    }

    for slot in envelope.slot().as_u64().saturating_add(1)..split.slot.as_u64() {
        let Some(next_root_bytes) = db
            .cold_db
            .get_bytes(DBColumn::BeaconBlockRoots, &slot.to_be_bytes())?
        else {
            return Ok(false);
        };
        let next_root = Hash256::from_ssz_bytes(&next_root_bytes)?;
        if next_root != block_root {
            return child_selects_empty::<T>(db, block_root, next_root, envelope);
        }
    }

    child_selects_empty::<T>(db, block_root, split.block_root, envelope)
}

fn child_selects_empty<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    block_root: Hash256,
    child_root: Hash256,
    envelope: &SignedExecutionPayloadEnvelope<T::EthSpec>,
) -> Result<bool, StoreError> {
    if child_root == block_root {
        return Ok(false);
    }
    // A partially backfilled database may not have the child block. Without it, the payload
    // status cannot be determined, so preserve the envelope rather than aborting the upgrade.
    let Some(child) = db.get_blinded_block(&child_root)? else {
        return Ok(false);
    };
    Ok(child.parent_root() == block_root
        && !child.is_parent_block_full(envelope.message.payload.block_hash))
}

/// Downgrade from schema v31 to v30.
///
/// This downgrade is only possible prior to Gloas, when there are no payload envelope summaries.
pub fn downgrade_from_v31<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    if let Some(result) = db
        .hot_db
        .iter_column_keys::<Hash256>(DBColumn::PayloadSummary)
        .next()
    {
        let block_root = result?;
        return Err(StoreError::MigrationError(format!(
            "cannot downgrade from v31 to v30 after Gloas: found payload envelope summary for \
             block {block_root:?}"
        )));
    }

    Ok(vec![])
}
