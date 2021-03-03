//! Utilities for managing database schema changes.
use crate::beacon_chain::BeaconChainTypes;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use store::Error as StoreError;

const PUBKEY_CACHE_FILENAME: &str = "pubkey_cache.ssz";

/// Migrate the database from one schema version to another, applying all requisite mutations.
pub fn migrate_schema<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    datadir: &Path,
    from: SchemaVersion,
    to: SchemaVersion,
) -> Result<(), StoreError> {
    match (from, to) {
        // Migrating from the current schema version to iself is always OK, a no-op.
        (_, _) if from == to && to == CURRENT_SCHEMA_VERSION => Ok(()),
        // Migrate across multiple versions by recursively migrating one step at a time.
        (_, _) if from.as_u64() + 1 < to.as_u64() => {
            let next = SchemaVersion(from.as_u64() + 1);
            migrate_schema::<T>(db.clone(), datadir, from, next)?;
            migrate_schema::<T>(db, datadir, next, to)
        }
        // Migration from v0.3.0 to v0.3.x, adding the temporary states column.
        // Nothing actually needs to be done, but once a DB uses v2 it shouldn't go back.
        (SchemaVersion(1), SchemaVersion(2)) => {
            db.store_schema_version(to)?;
            Ok(())
        }
        // Migration for removing the pubkey cache.
        (SchemaVersion(2), SchemaVersion(3)) => {
            let pk_cache_path = datadir.join(PUBKEY_CACHE_FILENAME);

            // Load from file, store to DB.
            ValidatorPubkeyCache::<T>::load_from_file(&pk_cache_path)
                .and_then(|cache| ValidatorPubkeyCache::convert(cache, db.clone()))
                .map_err(|e| StoreError::SchemaMigrationError(format!("{:?}", e)))?;

            db.store_schema_version(to)?;

            // Delete cache file now that keys are stored in the DB.
            fs::remove_file(&pk_cache_path).map_err(|e| {
                StoreError::SchemaMigrationError(format!(
                    "unable to delete {}: {:?}",
                    pk_cache_path.display(),
                    e
                ))
            })?;

            Ok(())
        }
        // Anything else is an error.
        (_, _) => Err(HotColdDBError::UnsupportedSchemaVersion {
            target_version: to,
            current_version: from,
        }
        .into()),
    }
}
