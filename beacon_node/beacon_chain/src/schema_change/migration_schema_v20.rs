use crate::BeaconChainTypes;
use slog::{info, Logger};
use std::sync::Arc;
use store::{get_key_for_col, DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp};
use types::{Hash256, Slot};

/// Chunk size for freezer block roots in the old database schema.
const OLD_SCHEMA_CHUNK_SIZE: u64 = 128;

fn old_schema_chunk_key(cindex: u64) -> [u8; 8] {
    (cindex + 1).to_be_bytes()
}

pub fn upgrade_to_v20<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!(log, "Upgrading freezer database schema");
    upgrade_freezer_database::<T>(&db, &log)?;

    // No hot DB changes
    return Ok(vec![]);
}

fn upgrade_freezer_database<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    log: &Logger,
) -> Result<(), Error> {
    let mut cold_db_ops = vec![];

    // Re-write the beacon block roots array.
    let mut freezer_block_roots = vec![];
    let oldest_block_slot = db.get_oldest_block_slot();
    let mut current_slot = oldest_block_slot;

    for result in db
        .cold_db
        .iter_column::<Vec<u8>>(DBColumn::BeaconBlockRoots)
    {
        let (chunk_key, chunk_bytes) = result?;

        // Stage this chunk for deletion.
        cold_db_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
            DBColumn::BeaconBlockRoots.into(),
            &chunk_key,
        )));

        // Skip the 0x0 key which is for the genesis block.
        if chunk_key.iter().all(|b| *b == 0u8) {
            continue;
        }
        // Skip the 0x00..01 key which is for slot 0.
        if chunk_key == old_schema_chunk_key(0).as_slice() && current_slot != 0 {
            continue;
        }

        let current_chunk_index = current_slot.as_u64() / OLD_SCHEMA_CHUNK_SIZE;
        if chunk_key != old_schema_chunk_key(current_chunk_index).as_slice() {
            return Err(Error::DBError {
                message: format!(
                    "expected chunk index {} but got {:?}",
                    current_chunk_index, chunk_key
                ),
            });
        }

        for (i, block_root_bytes) in chunk_bytes.chunks_exact(32).enumerate() {
            let block_root = Hash256::from_slice(block_root_bytes);

            if block_root.is_zero() {
                continue;
            }

            let slot = Slot::new(current_chunk_index * OLD_SCHEMA_CHUNK_SIZE + i as u64);
            if slot != current_slot {
                return Err(Error::DBError {
                    message: format!(
                        "expected block root for slot {} but got {}",
                        current_slot, slot
                    ),
                });
            }
            freezer_block_roots.push((slot, block_root));
            current_slot += 1;
        }
    }

    // Write the freezer block roots in the new schema.
    for (slot, block_root) in freezer_block_roots {
        cold_db_ops.push(KeyValueStoreOp::PutKeyValue(
            get_key_for_col(
                DBColumn::BeaconBlockRoots.into(),
                &slot.as_u64().to_be_bytes(),
            ),
            block_root.as_bytes().to_vec(),
        ));
    }

    db.cold_db.do_atomically(cold_db_ops)?;
    info!(
        log,
        "Freezer database upgrade complete";
        "oldest_block_slot" => oldest_block_slot,
        "newest_block_slot" => current_slot - 1
    );

    Ok(())
}
