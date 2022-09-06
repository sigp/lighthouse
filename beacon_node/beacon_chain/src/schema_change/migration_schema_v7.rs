///! These functions and structs are only relevant to the database migration from schema 6 to 7.
use crate::beacon_chain::BeaconChainTypes;
use crate::beacon_fork_choice_store::{PersistedForkChoiceStoreV1, PersistedForkChoiceStoreV7};
use crate::persisted_fork_choice::{PersistedForkChoiceV1, PersistedForkChoiceV7};
use crate::schema_change::types::{ProtoNodeV6, SszContainerV10, SszContainerV6, SszContainerV7};
use crate::types::{ChainSpec, Checkpoint, Epoch, EthSpec, Hash256, Slot};
use crate::{BeaconForkChoiceStore, BeaconSnapshot};
use fork_choice::ForkChoice;
use proto_array::{core::ProtoNode, core::SszContainer, CountUnrealizedFull, ProtoArrayForkChoice};
use ssz::four_byte_option_impl;
use ssz::{Decode, Encode};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use store::hot_cold_store::HotColdDB;
use store::iter::BlockRootsIterator;
use store::Error as StoreError;

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);

/// This method is used to re-initialize fork choice from the finalized state in case we hit an
/// error during this migration.
pub(crate) fn update_with_reinitialized_fork_choice<T: BeaconChainTypes>(
    persisted_fork_choice: &mut PersistedForkChoiceV7,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    spec: &ChainSpec,
) -> Result<(), String> {
    let anchor_block_root = persisted_fork_choice
        .fork_choice_store
        .finalized_checkpoint
        .root;
    let anchor_block = db
        .get_full_block_prior_to_v9(&anchor_block_root)
        .map_err(|e| format!("{:?}", e))?
        .ok_or_else(|| "Missing anchor beacon block".to_string())?;
    let anchor_state = db
        .get_state(&anchor_block.state_root(), Some(anchor_block.slot()))
        .map_err(|e| format!("{:?}", e))?
        .ok_or_else(|| "Missing anchor beacon state".to_string())?;
    let snapshot = BeaconSnapshot {
        beacon_block: Arc::new(anchor_block),
        beacon_block_root: anchor_block_root,
        beacon_state: anchor_state,
    };
    let store = BeaconForkChoiceStore::get_forkchoice_store(db, &snapshot);
    let fork_choice = ForkChoice::from_anchor(
        store,
        anchor_block_root,
        &snapshot.beacon_block,
        &snapshot.beacon_state,
        // Don't provide the current slot here, just use what's in the store. We don't need to know
        // the head here, plus it's nice to avoid mutating fork choice during this process.
        None,
        // This config will get overwritten on startup.
        CountUnrealizedFull::default(),
        spec,
    )
    .map_err(|e| format!("{:?}", e))?;
    persisted_fork_choice.fork_choice = fork_choice.to_persisted();
    Ok(())
}

pub(crate) fn update_fork_choice<T: BeaconChainTypes>(
    persisted_fork_choice: &mut PersistedForkChoiceV7,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<(), StoreError> {
    // `PersistedForkChoice` stores the `ProtoArray` as a `Vec<u8>`. Deserialize these
    // bytes assuming the legacy struct, and transform them to the new struct before
    // re-serializing.
    let ssz_container_v6 =
        SszContainerV6::from_ssz_bytes(&persisted_fork_choice.fork_choice.proto_array_bytes)
            .map_err(|e| {
                StoreError::SchemaMigrationError(format!(
                    "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
                    e
                ))
            })?;

    // Clone the V6 proto nodes in order to maintain information about `node.justified_epoch`
    // and `node.finalized_epoch`.
    let nodes_v6 = ssz_container_v6.nodes.clone();

    let justified_checkpoint = persisted_fork_choice.fork_choice_store.justified_checkpoint;
    let finalized_checkpoint = persisted_fork_choice.fork_choice_store.finalized_checkpoint;

    // These transformations instantiate `node.justified_checkpoint` and `node.finalized_checkpoint`
    // to `None`.
    let ssz_container_v7: SszContainerV7 =
        ssz_container_v6.into_ssz_container_v7(justified_checkpoint, finalized_checkpoint);
    let ssz_container_v10: SszContainerV10 = ssz_container_v7.into();
    let ssz_container: SszContainer = ssz_container_v10.into();
    // `CountUnrealizedFull::default()` represents the count-unrealized-full config which will be overwritten on startup.
    let mut fork_choice: ProtoArrayForkChoice =
        (ssz_container, CountUnrealizedFull::default()).into();

    update_checkpoints::<T>(finalized_checkpoint.root, &nodes_v6, &mut fork_choice, db)
        .map_err(StoreError::SchemaMigrationError)?;

    // Update the justified checkpoint in the store in case we have a discrepancy
    // between the store and the proto array nodes.
    update_store_justified_checkpoint(persisted_fork_choice, &mut fork_choice)
        .map_err(StoreError::SchemaMigrationError)?;

    // Need to downgrade the SSZ container to V7 so that all migrations can be applied in sequence.
    let ssz_container = SszContainer::from(&fork_choice);
    let ssz_container_v7 = SszContainerV7::from(ssz_container);

    persisted_fork_choice.fork_choice.proto_array_bytes = ssz_container_v7.as_ssz_bytes();
    persisted_fork_choice.fork_choice_store.justified_checkpoint = justified_checkpoint;

    Ok(())
}

struct HeadInfo {
    index: usize,
    root: Hash256,
    slot: Slot,
}

fn update_checkpoints<T: BeaconChainTypes>(
    finalized_root: Hash256,
    nodes_v6: &[ProtoNodeV6],
    fork_choice: &mut ProtoArrayForkChoice,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<(), String> {
    let heads = find_finalized_descendant_heads(finalized_root, fork_choice);

    // For each head, first gather all epochs we will need to find justified or finalized roots for.
    for head in heads {
        // `relevant_epochs` are epochs for which we will need to find the root at the start slot.
        // We don't need to worry about whether the are finalized or justified epochs.
        let mut relevant_epochs = HashSet::new();
        let relevant_epoch_finder = |index, _: &mut ProtoNode| {
            let (justified_epoch, finalized_epoch) = nodes_v6
                .get(index)
                .map(|node: &ProtoNodeV6| (node.justified_epoch, node.finalized_epoch))
                .ok_or_else(|| "Index not found in legacy proto nodes".to_string())?;
            relevant_epochs.insert(justified_epoch);
            relevant_epochs.insert(finalized_epoch);
            Ok(())
        };

        apply_to_chain_of_ancestors(
            finalized_root,
            head.index,
            fork_choice,
            relevant_epoch_finder,
        )?;

        // find the block roots associated with each relevant epoch.
        let roots_by_epoch =
            map_relevant_epochs_to_roots::<T>(head.root, head.slot, relevant_epochs, db.clone())?;

        // Apply this mutator to the chain of descendants from this head, adding justified
        // and finalized checkpoints for each.
        let node_mutator = |index, node: &mut ProtoNode| {
            let (justified_epoch, finalized_epoch) = nodes_v6
                .get(index)
                .map(|node: &ProtoNodeV6| (node.justified_epoch, node.finalized_epoch))
                .ok_or_else(|| "Index not found in legacy proto nodes".to_string())?;

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

        apply_to_chain_of_ancestors(finalized_root, head.index, fork_choice, node_mutator)?;
    }
    Ok(())
}

/// Coverts the given `HashSet<Epoch>` to a `Vec<Epoch>` then reverse sorts by `Epoch`. Next, a
/// single `BlockRootsIterator` is created which is used to iterate backwards from the given
/// `head_root` and `head_slot`, finding the block root at the start slot of each epoch.
fn map_relevant_epochs_to_roots<T: BeaconChainTypes>(
    head_root: Hash256,
    head_slot: Slot,
    epochs: HashSet<Epoch>,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<HashMap<Epoch, Hash256>, String> {
    // Convert the `HashSet` to a `Vec` and reverse sort the epochs.
    let mut relevant_epochs = epochs.into_iter().collect::<Vec<_>>();
    relevant_epochs.sort_unstable_by(|a, b| b.cmp(a));

    // Iterate backwards from the given `head_root` and `head_slot` and find the block root at each epoch.
    let mut iter = std::iter::once(Ok((head_root, head_slot)))
        .chain(BlockRootsIterator::from_block(&db, head_root).map_err(|e| format!("{:?}", e))?);
    let mut roots_by_epoch = HashMap::new();
    for epoch in relevant_epochs {
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

/// Applies a mutator to every node in a chain, starting from the node at the given
/// `head_index` and iterating through ancestors until the `finalized_root` is reached.
fn apply_to_chain_of_ancestors<F>(
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

    // Iterate backwards through all parents until there is no reference to a parent or we reach
    // the `finalized_root` node.
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

/// Finds all heads by finding all nodes in the proto array that are not referenced as parents. Then
/// checks that these nodes are descendants of the finalized root in order to determine if they are
/// relevant.
fn find_finalized_descendant_heads(
    finalized_root: Hash256,
    fork_choice: &ProtoArrayForkChoice,
) -> Vec<HeadInfo> {
    let nodes_referenced_as_parents: HashSet<usize> = fork_choice
        .core_proto_array()
        .nodes
        .iter()
        .filter_map(|node| node.parent)
        .collect::<HashSet<_>>();

    fork_choice
        .core_proto_array()
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (!nodes_referenced_as_parents.contains(&index)
                && fork_choice.is_descendant(finalized_root, node.root))
            .then(|| HeadInfo {
                index,
                root: node.root,
                slot: node.slot,
            })
        })
        .collect::<Vec<_>>()
}

fn update_store_justified_checkpoint(
    persisted_fork_choice: &mut PersistedForkChoiceV7,
    fork_choice: &mut ProtoArrayForkChoice,
) -> Result<(), String> {
    let justified_checkpoint = fork_choice
        .core_proto_array()
        .nodes
        .iter()
        .filter_map(|node| {
            (node.finalized_checkpoint
                == Some(persisted_fork_choice.fork_choice_store.finalized_checkpoint))
            .then(|| node.justified_checkpoint)
            .flatten()
        })
        .max_by_key(|justified_checkpoint| justified_checkpoint.epoch)
        .ok_or("Proto node with current finalized checkpoint not found")?;

    fork_choice.core_proto_array_mut().justified_checkpoint = justified_checkpoint;
    Ok(())
}

// Add a zero `proposer_boost_root` when migrating from V1-6 to V7.
impl From<PersistedForkChoiceStoreV1> for PersistedForkChoiceStoreV7 {
    fn from(other: PersistedForkChoiceStoreV1) -> Self {
        Self {
            balances_cache: other.balances_cache,
            time: other.time,
            finalized_checkpoint: other.finalized_checkpoint,
            justified_checkpoint: other.justified_checkpoint,
            justified_balances: other.justified_balances,
            best_justified_checkpoint: other.best_justified_checkpoint,
            proposer_boost_root: Hash256::zero(),
        }
    }
}

impl From<PersistedForkChoiceV1> for PersistedForkChoiceV7 {
    fn from(other: PersistedForkChoiceV1) -> Self {
        Self {
            fork_choice: other.fork_choice,
            fork_choice_store: other.fork_choice_store.into(),
        }
    }
}
