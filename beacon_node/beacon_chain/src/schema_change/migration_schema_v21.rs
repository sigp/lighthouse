use crate::beacon_chain::BeaconChainTypes;
use crate::validator_pubkey_cache::DatabasePubkey;
use slog::{debug, Logger};
use ssz::Decode;
use std::sync::Arc;
use store::{DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreItem};
use types::{Hash256, PublicKey};

const LOG_EVERY: usize = 100_000;

pub fn upgrade_to_v21<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let mut ops = vec![];

    debug!(log, "Migrating from v20 to v21");

    // Iterate through all pubkeys and decompress them.
    for (i, res) in db
        .hot_db
        .iter_column::<Hash256>(DBColumn::PubkeyCache)
        .enumerate()
    {
        let (key, value) = res?;
        let pubkey = PublicKey::from_ssz_bytes(&value)?;
        let compressed = DatabasePubkey::from_pubkey(&pubkey);
        ops.push(compressed.as_kv_store_op(key));

        if i > 0 && i % LOG_EVERY == 0 {
            debug!(
                log,
                "Public key decompression in progress";
                "keys_decompressed" => i
            );
        }
    }
    debug!(log, "Public key decompression complete");

    Ok(ops)
}

pub fn downgrade_from_v21<T: BeaconChainTypes>(
    _db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    _log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // TODO(sproul): impl downgrade
    Ok(vec![])
}
