use crate::beacon_chain::BeaconChainTypes;
use store::hot_cold_store::HotColdDB;
use store::{DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};

/// Upgrade from schema v29 to v30.
///
/// Rewrites `DBColumn::LightClientUpdate` keys from little-endian to big-endian
/// `u64` sync committee period encoding. LE-encoded keys don't sort in numeric
/// order, which broke `iter_column_from` range scans across period-256
/// boundaries in `get_light_client_updates`. See #9472.
///
/// The value bytes (SSZ-encoded `LightClientUpdate`) are unchanged; only the
/// key encoding changes.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn upgrade_to_v30<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let column = DBColumn::LightClientUpdate;
    let mut ops = vec![];

    for res in db.hot_db.iter_column::<Vec<u8>>(column) {
        let (old_le_key, value_bytes) = res?;

        let period = u64::from_le_bytes(old_le_key.as_slice().try_into().map_err(|_| {
            StoreError::MigrationError(format!(
                "cannot upgrade from v29 to v30: unexpected LightClientUpdate key length {} \
                 (expected 8 bytes)",
                old_le_key.len(),
            ))
        })?);

        ops.push(KeyValueStoreOp::DeleteKey(column, old_le_key));
        ops.push(KeyValueStoreOp::PutKeyValue(
            column,
            period.to_be_bytes().to_vec(),
            value_bytes,
        ));
    }

    Ok(ops)
}

/// Downgrade from schema v30 to v29.
///
/// Rewrites `DBColumn::LightClientUpdate` keys from big-endian back to
/// little-endian `u64` sync committee period encoding.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn downgrade_from_v30<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let column = DBColumn::LightClientUpdate;
    let mut ops = vec![];

    for res in db.hot_db.iter_column::<Vec<u8>>(column) {
        let (old_be_key, value_bytes) = res?;

        let period = u64::from_be_bytes(old_be_key.as_slice().try_into().map_err(|_| {
            StoreError::MigrationError(format!(
                "cannot downgrade from v30 to v29: unexpected LightClientUpdate key length {} \
                 (expected 8 bytes)",
                old_be_key.len(),
            ))
        })?);

        ops.push(KeyValueStoreOp::DeleteKey(column, old_be_key));
        ops.push(KeyValueStoreOp::PutKeyValue(
            column,
            period.to_le_bytes().to_vec(),
            value_bytes,
        ));
    }

    Ok(ops)
}
