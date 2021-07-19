use crate::*;
use ssz::Encode;

pub mod beacon_state;

/// Prepare a signed beacon block for storage in the database.
#[must_use]
pub fn beacon_block_as_kv_store_op<T: EthSpec>(
    key: &Hash256,
    block: &SignedBeaconBlock<T>,
) -> KeyValueStoreOp {
    // FIXME(altair): re-add block write/overhead metrics, or remove them
    let db_key = get_key_for_col(DBColumn::BeaconBlock.into(), key.as_bytes());
    KeyValueStoreOp::PutKeyValue(db_key, block.as_ssz_bytes())
}
