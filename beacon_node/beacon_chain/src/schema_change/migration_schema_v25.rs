use store::{DBColumn, Error, KeyValueStoreOp};
use tracing::info;
use types::Hash256;

pub const ETH1_CACHE_DB_KEY: Hash256 = Hash256::ZERO;

/// Delete the on-disk eth1 data.
pub fn upgrade_to_v25() -> Result<Vec<KeyValueStoreOp>, Error> {
    info!("Deleting eth1 data from disk for v25 DB upgrade");
    Ok(vec![KeyValueStoreOp::DeleteKey(
        DBColumn::Eth1Cache,
        ETH1_CACHE_DB_KEY.as_slice().to_vec(),
    )])
}

/// No-op: we don't need to recreate on-disk eth1 data, as previous versions gracefully handle
/// data missing from disk.
pub fn downgrade_from_v25() -> Result<Vec<KeyValueStoreOp>, Error> {
    Ok(vec![])
}
