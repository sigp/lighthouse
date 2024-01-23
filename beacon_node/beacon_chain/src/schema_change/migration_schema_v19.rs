use crate::beacon_chain::BeaconChainTypes;
use slog::{debug, info, Logger};
use std::sync::Arc;
use store::{get_key_for_col, DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp};

pub fn upgrade_to_v19<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let mut hot_delete_ops = vec![];
    let mut blob_keys = vec![];
    let column = DBColumn::BeaconBlob;

    debug!(log, "Migrating from v18 to v19");
    // Iterate throught the blobs on disk.
    for res in db.hot_db.iter_column_keys::<Vec<u8>>(column) {
        let key = res?;
        let key_col = get_key_for_col(column.as_str(), &key);
        hot_delete_ops.push(KeyValueStoreOp::DeleteKey(key_col));
        blob_keys.push(key);
    }
    let num_blobs = blob_keys.len();
    debug!(log, "Collected {} blob lists to migrate", num_blobs);

    for key in blob_keys {
        let next_blob = db.hot_db.get_bytes(column.as_str(), &key)?;
        if let Some(next_blob) = next_blob {
            let key_col = get_key_for_col(column.as_str(), &key);
            db.blobs_db
                .do_atomically(vec![KeyValueStoreOp::PutKeyValue(key_col, next_blob)])?;
        }
    }
    debug!(log, "Wrote {} blobs to the blobs db", num_blobs);

    // Delete all the blobs
    info!(
        log,
        "Upgrading to v19 schema";
        "info" => "ready for Deneb once it is scheduled"
    );
    Ok(hot_delete_ops)
}

pub fn downgrade_from_v19<T: BeaconChainTypes>(
    _db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // No-op
    info!(
        log,
        "Downgrading to v18 schema";
    );

    Ok(vec![])
}
