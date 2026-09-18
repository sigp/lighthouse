use crate::beacon_chain::BeaconChainTypes;
use std::cmp::{max, min};
use store::hot_cold_store::HotColdDB;
use store::metadata::{
    BLOB_INFO_KEY, BlobInfo, DATA_COLUMN_INFO_KEY, DATA_INFO_KEY, DataColumnInfo, DataInfo,
};
use store::{DBColumn, Error as StoreError, ItemStore, KeyValueStoreOp, StoreItem};
use tracing::info;
use types::EthSpec;

/// Upgrade from schema v30 to v31.
///
/// Merges the legacy `BlobInfo` and `DataColumnInfo` metadata into the single `DataInfo`, which
/// tracks one low-water mark for all sidecar data (blobs pre-Fulu, data columns from Fulu
/// onwards).
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn upgrade_to_v31<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let oldest_blob_slot = db
        .hot_db
        .get::<BlobInfo>(&BLOB_INFO_KEY)?
        .and_then(|blob_info| blob_info.oldest_blob_slot);
    let oldest_data_column_slot = db
        .hot_db
        .get::<DataColumnInfo>(&DATA_COLUMN_INFO_KEY)?
        .and_then(|data_column_info| data_column_info.oldest_data_column_slot);

    let oldest_data_slot = match (oldest_blob_slot, oldest_data_column_slot) {
        (Some(blob_slot), Some(column_slot)) => {
            // If the blob marker lies in a PeerDAS epoch then no blobs can exist before it: it
            // was either initialized at a post-Fulu anchor (fresh checkpoint sync) or advanced
            // past the fork by the final blob prune, and was never updated since. In the latter
            // case that final prune also deleted the data columns up to the blob marker but left
            // the column marker stale at the Fulu fork slot, so taking the newer of the two
            // markers avoids claiming data that has been pruned. This can overshoot in the
            // former case (backfill lowers only the column marker, leaving the blob marker at
            // the anchor), which merely under-advertises backfilled columns until pruning
            // advances the marker past the anchor. Outside PeerDAS epochs pre-Fulu blobs may
            // still be stored (e.g. on nodes with blob pruning disabled) and the older of the
            // two markers is correct.
            if db
                .spec
                .is_peer_das_enabled_for_epoch(blob_slot.epoch(T::EthSpec::slots_per_epoch()))
            {
                max(blob_slot, column_slot)
            } else {
                min(blob_slot, column_slot)
            }
        }
        (Some(blob_slot), None) => blob_slot,
        (None, Some(column_slot)) => column_slot,
        (None, None) => {
            return Err(StoreError::MigrationError(
                "No BlobInfo or DataColumnInfo found".to_string(),
            ));
        }
    };

    info!(
        ?oldest_blob_slot,
        ?oldest_data_column_slot,
        %oldest_data_slot,
        "Merging blob info and data column info into data info"
    );

    // `DATA_INFO_KEY` cannot exist on disk before this migration runs: fresh databases start at
    // the current schema version, and the only tool that writes it without migrating first
    // (`lighthouse db prune-blobs`) refuses to run on pre-v31 schemas. The merged legacy value is
    // therefore always the true marker. Update the in-memory data info (still the default, as
    // `open()` found no `DATA_INFO_KEY`) along with staging the on-disk write.
    let put_data_info_op =
        db.compare_and_set_data_info(db.get_data_info(), DataInfo { oldest_data_slot })?;

    Ok(vec![
        put_data_info_op,
        KeyValueStoreOp::DeleteKey(DBColumn::BeaconMeta, BLOB_INFO_KEY.as_slice().to_vec()),
        KeyValueStoreOp::DeleteKey(
            DBColumn::BeaconMeta,
            DATA_COLUMN_INFO_KEY.as_slice().to_vec(),
        ),
    ])
}

/// Downgrade from schema v31 to v30.
///
/// Splits `DataInfo` back into the legacy `BlobInfo` and `DataColumnInfo` at the Fulu fork
/// boundary.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn downgrade_from_v31<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let oldest_data_slot = db.get_data_info().oldest_data_slot;

    let blob_info = BlobInfo {
        oldest_blob_slot: Some(oldest_data_slot),
        blobs_db: true,
    };
    let data_column_info = DataColumnInfo {
        // Data columns exist from the Fulu fork at the earliest.
        oldest_data_column_slot: db.spec.fulu_fork_epoch.map(|fork_epoch| {
            max(
                oldest_data_slot,
                fork_epoch.start_slot(T::EthSpec::slots_per_epoch()),
            )
        }),
    };

    info!(
        %oldest_data_slot,
        oldest_blob_slot = ?blob_info.oldest_blob_slot,
        oldest_data_column_slot = ?data_column_info.oldest_data_column_slot,
        "Splitting data info into blob info and data column info"
    );

    Ok(vec![
        blob_info.as_kv_store_op(BLOB_INFO_KEY),
        data_column_info.as_kv_store_op(DATA_COLUMN_INFO_KEY),
        KeyValueStoreOp::DeleteKey(DBColumn::BeaconMeta, DATA_INFO_KEY.as_slice().to_vec()),
    ])
}
