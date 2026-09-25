//! Utilities for managing database schema changes.
mod migration_schema_v29;
mod migration_schema_v30;
mod migration_schema_v31;

use crate::beacon_chain::BeaconChainTypes;
use migration_schema_v29::{downgrade_from_v29, upgrade_to_v29};
use migration_schema_v30::{downgrade_from_v30, upgrade_to_v30};
use migration_schema_v31::{downgrade_from_v31, upgrade_to_v31};
use std::sync::Arc;
use store::Error as StoreError;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{CURRENT_SCHEMA_VERSION, OLDEST_SUPPORTED_SCHEMA_VERSION, SchemaVersion};

/// Migrate the database from one schema version to another, applying all requisite mutations.
///
/// Migrations from schema versions older than `OLDEST_SUPPORTED_SCHEMA_VERSION` have been removed.
pub fn migrate_schema<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    from: SchemaVersion,
    to: SchemaVersion,
) -> Result<(), StoreError> {
    match (from, to) {
        // Upgrade from v28 to v29.
        (SchemaVersion(28), SchemaVersion(29)) => {
            let ops = upgrade_to_v29::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v29 to v28.
        (SchemaVersion(29), SchemaVersion(28)) => {
            let ops = downgrade_from_v29::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Upgrade from v29 to v30.
        (SchemaVersion(29), SchemaVersion(30)) => {
            let ops = upgrade_to_v30::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v30 to v29.
        (SchemaVersion(30), SchemaVersion(29)) => {
            let ops = downgrade_from_v30::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Upgrade from v30 to v31.
        (SchemaVersion(30), SchemaVersion(31)) => {
            let ops = upgrade_to_v31::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v31 to v30.
        (SchemaVersion(31), SchemaVersion(30)) => {
            let ops = downgrade_from_v31::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Chain multi-step upgrades and downgrades through the intermediate versions, e.g.
        // v29 -> v31 as v29 -> v30 -> v31. Every adjacent pair of versions within
        // [OLDEST_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION] has a single-step arm above, so
        // requiring both endpoints to lie in that range means every step is supported; anything
        // outside it falls through to the error arm untouched.
        //
        // Each step is committed before the next one runs, as a migration reads what the
        // previous one wrote. A failing step therefore leaves the database at the last version
        // that did commit, which the error names so that the operator can retry from there.
        (_, _)
            if from >= OLDEST_SUPPORTED_SCHEMA_VERSION
                && to >= OLDEST_SUPPORTED_SCHEMA_VERSION
                && from <= CURRENT_SCHEMA_VERSION
                && to <= CURRENT_SCHEMA_VERSION =>
        {
            let mut current = from;
            while current != to {
                let step = if current < to {
                    SchemaVersion(current.as_u64() + 1)
                } else {
                    SchemaVersion(current.as_u64() - 1)
                };
                migrate_schema::<T>(db.clone(), current, step).map_err(|e| {
                    if current == from {
                        // Nothing has been committed, so the error stands on its own.
                        e
                    } else {
                        StoreError::MigrationError(format!(
                            "migrating from v{} to v{} failed at v{} -> v{}; the database is now \
                             at v{}: {:?}",
                            from.as_u64(),
                            to.as_u64(),
                            current.as_u64(),
                            step.as_u64(),
                            current.as_u64(),
                            e,
                        ))
                    }
                })?;
                current = step;
            }
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
