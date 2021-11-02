//! Utilities for managing database schema changes.
use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY};
use crate::persisted_fork_choice::PersistedForkChoice;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use operation_pool::{PersistedOperationPool, PersistedOperationPoolBase};
use proto_array::{ProtoArrayForkChoice, core::ProtoNode, core::SszContainer, core::VoteTracker};
use ssz::{Decode, Encode};
use ssz::four_byte_option_impl;
use ssz_derive::{Decode, Encode};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use store::config::OnDiskStoreConfig;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{SchemaVersion, CONFIG_KEY, CURRENT_SCHEMA_VERSION};
use store::{DBColumn, Error as StoreError, ItemStore, StoreItem};
use crate::types::{Epoch, Hash256};
use proto_array::ExecutionStatus;
use crate::types::{AttestationShufflingId, Slot};

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
        // Migration for adding sync committee contributions to the persisted op pool.
        (SchemaVersion(3), SchemaVersion(4)) => {
            // Deserialize from what exists in the database using the `PersistedOperationPoolBase`
            // variant and convert it to the Altair variant.
            let pool_opt = db
                .get_item::<PersistedOperationPoolBase<T::EthSpec>>(&OP_POOL_DB_KEY)?
                .map(PersistedOperationPool::Base)
                .map(PersistedOperationPool::base_to_altair);

            if let Some(pool) = pool_opt {
                // Store the converted pool under the same key.
                db.put_item::<PersistedOperationPool<T::EthSpec>>(&OP_POOL_DB_KEY, &pool)?;
            }

            db.store_schema_version(to)?;

            Ok(())
        }
        // Migration for weak subjectivity sync support and clean up of `OnDiskStoreConfig` (#1784).
        (SchemaVersion(4), SchemaVersion(5)) => {
            if let Some(OnDiskStoreConfigV4 {
                slots_per_restore_point,
                ..
            }) = db.hot_db.get(&CONFIG_KEY)?
            {
                let new_config = OnDiskStoreConfig {
                    slots_per_restore_point,
                };
                db.hot_db.put(&CONFIG_KEY, &new_config)?;
            }

            db.store_schema_version(to)?;

            Ok(())
        }
        // Migration for adding `is_merge_complete` field to the fork choice store.
        (SchemaVersion(5), SchemaVersion(6)) => {
            let fork_choice_opt = db
                .get_item::<PersistedForkChoice>(&FORK_CHOICE_DB_KEY)?
                .map(|mut persisted_fork_choice| {
                    let fork_choice = proto_array_from_legacy_bytes(
                        &persisted_fork_choice.fork_choice.proto_array_bytes,
                    )?;
                    persisted_fork_choice.fork_choice.proto_array_bytes = fork_choice.as_bytes();
                    Ok::<_, String>(persisted_fork_choice)
                })
                .transpose()
                .map_err(StoreError::SchemaMigrationError)?;
            if let Some(fork_choice) = fork_choice_opt {
                // Store the converted fork choice store under the same key.
                db.put_item::<PersistedForkChoice>(&FORK_CHOICE_DB_KEY, &fork_choice)?;
            }

            db.store_schema_version(to)?;

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

// Store config used in v4 schema and earlier.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OnDiskStoreConfigV4 {
    pub slots_per_restore_point: u64,
    pub _block_cache_size: usize,
}

impl StoreItem for OnDiskStoreConfigV4 {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);

/// Only used for SSZ deserialization of the persisted fork choice during the database migration
/// from schema 4 to schema 5.
pub fn proto_array_from_legacy_bytes(bytes: &[u8]) -> Result<ProtoArrayForkChoice, String> {
    LegacySszContainer::from_ssz_bytes(bytes)
        .map(|legacy_container| {
            let container: SszContainer = legacy_container.into();
            container.into()
        })
        .map_err(|e| {
            format!(
                "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
                e
            )
        })
}

// Only used for SSZ deserialization of the persisted fork choice during the database migration
/// from schema 4 to schema 5.
#[derive(Encode, Decode)]
pub struct LegacySszContainer {
    votes: Vec<VoteTracker>,
    balances: Vec<u64>,
    prune_threshold: usize,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    nodes: Vec<LegacyProtoNode>,
    indices: Vec<(Hash256, usize)>,
}


impl Into<SszContainer> for LegacySszContainer {
    fn into(self) -> SszContainer {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainer {
            votes: self.votes,
            balances: self.balances,
            prune_threshold: self.prune_threshold,
            justified_epoch: self.justified_epoch,
            finalized_epoch: self.finalized_epoch,
            nodes,
            indices: self.indices,
        }
    }
}

/// Only used for SSZ deserialization of the persisted fork choice during the database migration
/// from schema 4 to schema 5.
#[derive(Encode, Decode)]
pub struct LegacyProtoNode {
    pub slot: Slot,
    pub state_root: Hash256,
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub root: Hash256,
    #[ssz(with = "four_byte_option_usize")]
    pub parent: Option<usize>,
    pub justified_epoch: Epoch,
    pub finalized_epoch: Epoch,
    weight: u64,
    #[ssz(with = "four_byte_option_usize")]
    best_child: Option<usize>,
    #[ssz(with = "four_byte_option_usize")]
    best_descendant: Option<usize>,
}

impl Into<ProtoNode> for LegacyProtoNode {
    fn into(self) -> ProtoNode {
        ProtoNode {
            slot: self.slot,
            state_root: self.state_root,
            target_root: self.target_root,
            current_epoch_shuffling_id: self.current_epoch_shuffling_id,
            next_epoch_shuffling_id: self.next_epoch_shuffling_id,
            root: self.root,
            parent: self.parent,
            justified_epoch: self.justified_epoch,
            finalized_epoch: self.finalized_epoch,
            weight: self.weight,
            best_child: self.best_child,
            best_descendant: self.best_descendant,
            // We set the following execution value as if the block is a pre-merge-fork block. This
            // is safe as long as we never import a merge block with the old version of proto-array.
            // This will be safe since we can't actually process merge blocks until we've made this
            // change to fork choice.
            execution_status: ExecutionStatus::irrelevant(),
        }
    }
}