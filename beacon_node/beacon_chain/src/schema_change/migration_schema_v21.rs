use crate::beacon_chain::BeaconChainTypes;
use crate::validator_pubkey_cache::DatabasePubkey;
use ssz::{Decode, Encode};
use std::sync::Arc;
use store::{
    get_key_for_col, DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreItem,
};
use tracing::info;
use types::{Hash256, PublicKey};

const LOG_EVERY: usize = 200_000;

pub fn upgrade_to_v21<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!("Upgrading from v20 to v21");

    let mut ops = vec![];

    // Iterate through all pubkeys and decompress them.
    for (i, res) in db
        .hot_db
        .iter_column::<Hash256>(DBColumn::PubkeyCache)
        .enumerate()
    {
        let (key, value) = res?;
        let pubkey = PublicKey::from_ssz_bytes(&value)?;
        let decompressed = DatabasePubkey::from_pubkey(&pubkey);
        ops.push(decompressed.as_kv_store_op(key));

        if i > 0 && i % LOG_EVERY == 0 {
            info!(
                keys_decompressed = i,
                "Public key decompression in progress"
            );
        }
    }
    info!("Public key decompression complete");

    Ok(ops)
}

pub fn downgrade_from_v21<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!("Downgrading from v21 to v20");

    let mut ops = vec![];

    // Iterate through all pubkeys and recompress them.
    for (i, res) in db
        .hot_db
        .iter_column::<Hash256>(DBColumn::PubkeyCache)
        .enumerate()
    {
        let (key, value) = res?;
        let decompressed = DatabasePubkey::from_ssz_bytes(&value)?;
        let (_, pubkey_bytes) = decompressed.as_pubkey().map_err(|e| Error::DBError {
            message: format!("{e:?}"),
        })?;

        let db_key = get_key_for_col(DBColumn::PubkeyCache.into(), key.as_slice());
        ops.push(KeyValueStoreOp::PutKeyValue(
            db_key,
            pubkey_bytes.as_ssz_bytes(),
        ));

        if i > 0 && i % LOG_EVERY == 0 {
            info!(keys_compressed = i, "Public key compression in progress");
        }
    }

    info!("Public key compression complete");

    Ok(ops)
}
