//! Utilities for managing database schema changes.
use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY};
use crate::persisted_fork_choice::PersistedForkChoice;
use crate::types::{AttestationShufflingId, EthSpec, Slot};
use crate::types::{Checkpoint, Epoch, Hash256};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use operation_pool::{PersistedOperationPool, PersistedOperationPoolBase};
use proto_array::ExecutionStatus;
use proto_array::{core::ProtoNode, core::SszContainer, core::VoteTracker, ProtoArrayForkChoice};
use ssz::four_byte_option_impl;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use store::config::OnDiskStoreConfig;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::iter::BlockRootsIterator;
use store::metadata::{SchemaVersion, CONFIG_KEY, CURRENT_SCHEMA_VERSION};
use store::{DBColumn, Error as StoreError, ItemStore, StoreItem};

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
        // Migration for adding `execution_status` field to the fork choice store, as well as
        // updating `justified_epoch` to `justified_checkpoint` and `finalized_epoch` to
        // `finalized_checkpoint`.
        (SchemaVersion(5), SchemaVersion(6)) => {
            let fork_choice_opt = db
                .get_item::<PersistedForkChoice>(&FORK_CHOICE_DB_KEY)?
                .map(|mut persisted_fork_choice| {
                    let fork_choice =
                        proto_array_from_legacy_persisted::<T>(&persisted_fork_choice, db.clone())?;
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
pub fn proto_array_from_legacy_persisted<T: BeaconChainTypes>(
    persisted_fork_choice: &PersistedForkChoice,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<ProtoArrayForkChoice, String> {
    let legacy_container =
        LegacySszContainer::from_ssz_bytes(&persisted_fork_choice.fork_choice.proto_array_bytes)
            .map_err(|e| {
                format!(
                    "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
                    e
                )
            })?;

    // Clone the legacy proto nodes in order to maintain information about `node.justified_epoch`
    // and `node.finalized_epoch`.
    let legacy_nodes = legacy_container.nodes.clone();

    // These transformations instantiate `node.justified_checkpoint` and `node.finalized_checkpoint`
    // to `None`.
    let container: SszContainer = legacy_container.into_ssz_container(
        persisted_fork_choice.fork_choice_store.justified_checkpoint,
        persisted_fork_choice.fork_choice_store.finalized_checkpoint,
    );
    let mut fork_choice: ProtoArrayForkChoice = container.into();

    let finalized_root = persisted_fork_choice
        .fork_choice_store
        .finalized_checkpoint
        .root;

    update_roots::<T>(db, finalized_root, &legacy_nodes, &mut fork_choice)?;

    Ok(fork_choice)
}

struct HeadInfo {
    index: usize,
    root: Hash256,
    slot: Slot,
}

fn update_roots<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    finalized_root: Hash256,
    legacy_nodes: &[LegacyProtoNode],
    fork_choice: &mut ProtoArrayForkChoice,
) -> Result<(), String> {
    let heads = find_heads(finalized_root, fork_choice);

    // For each head, first gather all epochs we will need to find justified or finalized roots for.
    for head in heads {
        // `relevant_epochs` are epochs for which we will need to find the root at the start slot.
        // We don't need to worry about whether the are finalized or justified epochs.
        let mut relevant_epochs = vec![];
        let relevant_epoch_finder = |index, _: &mut ProtoNode| {
            let (justified_epoch, finalized_epoch) = legacy_nodes
                .get(index)
                .map(|node: &LegacyProtoNode| (node.justified_epoch, node.finalized_epoch))
                .ok_or_else(|| "Head index not found in legacy proto nodes".to_string())?;
            relevant_epochs.push(justified_epoch);
            relevant_epochs.push(finalized_epoch);
            Ok(())
        };

        apply_to_chain_of_descendants(
            finalized_root,
            head.index,
            fork_choice,
            relevant_epoch_finder,
        )?;

        // Instantiate a block roots iter and iterate backwards to the start
        // of each justified or finalized epoch.
        let roots_by_epoch = map_relevant_epochs_to_roots::<T>(
            db.clone(),
            head.root,
            head.slot,
            &mut relevant_epochs,
        )?;

        // Iterate through the chain of descendants from this head and add justified checkpoints
        // and finalized checkpoints for each.
        let node_mutator = |index, node: &mut ProtoNode| {
            let (justified_epoch, finalized_epoch) = legacy_nodes
                .get(index)
                .map(|node: &LegacyProtoNode| (node.justified_epoch, node.finalized_epoch))
                .ok_or_else(|| "Head index not found in legacy proto nodes".to_string())?;

            // Update the checkpoints only if they haven't already been populated.
            if node.justified_checkpoint.is_none() {
                let justified_checkpoint =
                    roots_by_epoch
                        .get(&justified_epoch)
                        .map(|&root| Checkpoint {
                            epoch: justified_epoch,
                            root,
                        });
                node.justified_checkpoint = justified_checkpoint;
            }
            if node.finalized_checkpoint.is_none() {
                let finalized_checkpoint =
                    roots_by_epoch
                        .get(&finalized_epoch)
                        .map(|&root| Checkpoint {
                            epoch: finalized_epoch,
                            root,
                        });
                node.finalized_checkpoint = finalized_checkpoint;
            }

            Ok(())
        };

        apply_to_chain_of_descendants(finalized_root, head.index, fork_choice, node_mutator)?;
    }
    Ok(())
}

fn map_relevant_epochs_to_roots<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    head_root: Hash256,
    head_slot: Slot,
    relevant_epochs: &mut Vec<Epoch>,
) -> Result<HashMap<Epoch, Hash256>, String> {
    // Reverse sort the epochs and remove duplicates.
    relevant_epochs.sort_unstable_by(|a, b| b.cmp(a));
    relevant_epochs.dedup();

    // Iterate backwards, find root at each epoch.
    let mut iter = std::iter::once(Ok((head_root, head_slot)))
        .chain(BlockRootsIterator::from_block(db, head_root).map_err(|e| format!("{:?}", e))?);
    let mut roots_by_epoch = HashMap::new();
    for epoch in relevant_epochs.iter().copied() {
        let start_slot = epoch.start_slot(T::EthSpec::slots_per_epoch());

        let root = iter
            .find_map(|next| match next {
                Ok((root, slot)) => (slot == start_slot).then(|| Ok(root)),
                Err(e) => Some(Err(format!("{:?}", e))),
            })
            .transpose()?
            .ok_or_else(|| "Justified root not found".to_string())?;
        roots_by_epoch.insert(epoch, root);
    }
    Ok(roots_by_epoch)
}

fn apply_to_chain_of_descendants<F>(
    finalized_root: Hash256,
    head_index: usize,
    fork_choice: &mut ProtoArrayForkChoice,
    mut node_mutator: F,
) -> Result<(), String>
where
    F: FnMut(usize, &mut ProtoNode) -> Result<(), String>,
{
    let head = fork_choice
        .core_proto_array_mut()
        .nodes
        .get_mut(head_index)
        .ok_or_else(|| "Head index not found in proto nodes".to_string())?;

    node_mutator(head_index, head)?;

    let mut parent_index_opt = head.parent;
    let mut parent_opt =
        parent_index_opt.and_then(|index| fork_choice.core_proto_array_mut().nodes.get_mut(index));

    while let (Some(parent), Some(parent_index)) = (parent_opt, parent_index_opt) {
        node_mutator(parent_index, parent)?;

        // Break out of this while loop *after* the `node_mutator` has been applied to the finalized
        // node.
        if parent.root == finalized_root {
            break;
        }

        // Update parent values
        parent_index_opt = parent.parent;
        parent_opt = parent_index_opt
            .and_then(|index| fork_choice.core_proto_array_mut().nodes.get_mut(index));
    }
    Ok(())
}

fn find_heads(finalized_root: Hash256, fork_choice: &ProtoArrayForkChoice) -> Vec<HeadInfo> {
    let nodes_referenced_as_parents: Vec<usize> = fork_choice
        .core_proto_array()
        .nodes
        .iter()
        .filter_map(|node| node.parent)
        .collect::<Vec<_>>();

    fork_choice
        .core_proto_array()
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            if !nodes_referenced_as_parents.contains(&index)
                && fork_choice.is_descendant(finalized_root, node.root)
            {
                Some(HeadInfo {
                    index,
                    root: node.root,
                    slot: node.slot,
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
}

/// Only used for SSZ deserialization of the persisted fork choice during the database migration
/// from schema 4 to schema 5.
#[derive(Encode, Decode)]
pub struct LegacySszContainer {
    votes: Vec<VoteTracker>,
    balances: Vec<u64>,
    prune_threshold: usize,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    pub nodes: Vec<LegacyProtoNode>,
    indices: Vec<(Hash256, usize)>,
}

impl LegacySszContainer {
    fn into_ssz_container(
        self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
    ) -> SszContainer {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainer {
            votes: self.votes,
            balances: self.balances,
            prune_threshold: self.prune_threshold,
            justified_checkpoint,
            finalized_checkpoint,
            nodes,
            indices: self.indices,
        }
    }
}

/// Only used for SSZ deserialization of the persisted fork choice during the database migration
/// from schema 4 to schema 5.
#[derive(Encode, Decode, Clone)]
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
            justified_checkpoint: None,
            finalized_checkpoint: None,
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
