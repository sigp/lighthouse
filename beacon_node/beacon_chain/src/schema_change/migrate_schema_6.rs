use std::cmp::Ordering;
///! These functions and structs are only relevant to the database migration from schema 5 to 6.
use crate::beacon_chain::BeaconChainTypes;
use crate::persisted_fork_choice::PersistedForkChoice;
use crate::types::{AttestationShufflingId, EthSpec, Slot};
use crate::types::{Checkpoint, Epoch, Hash256};
use proto_array::ExecutionStatus;
use proto_array::{core::ProtoNode, core::SszContainer, core::VoteTracker, core::DEFAULT_PRUNE_THRESHOLD, ProtoArrayForkChoice};
use ssz::four_byte_option_impl;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::sync::Arc;
use slog::Logger;
use store::hot_cold_store::HotColdDB;
use store::iter::BlockRootsIterator;
use store::Error as StoreError;
use slog::{info, warn};
use itertools::Itertools;

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);

/// Only used for SSZ deserialization of the persisted fork choice during the database migration
/// from schema 5 to schema 6.
pub(crate) fn update_legacy_proto_array_bytes<T: BeaconChainTypes>(
    persisted_fork_choice: &mut PersistedForkChoice,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<(), String> {
    let legacy_container =
        LegacySszContainer::from_ssz_bytes(&persisted_fork_choice.fork_choice.proto_array_bytes)
            .map_err(|e| format!("Failed to decode ProtoArrayForkChoice during schema migration: {:?}", e))?;

    // Clone the legacy proto nodes in order to maintain information about `node.justified_epoch`
    // and `node.finalized_epoch`.
    let legacy_nodes = legacy_container.nodes.clone();

    let justified_checkpoint = persisted_fork_choice
        .fork_choice_store
        .get_justified_checkpoint();
    let finalized_checkpoint = persisted_fork_choice
        .fork_choice_store
        .get_finalized_checkpoint();

    // These transformations instantiate `node.justified_checkpoint` and `node.finalized_checkpoint`
    // to `None`.
    let container: SszContainer =
        legacy_container.into_ssz_container(justified_checkpoint, finalized_checkpoint);

    let mut fork_choice: ProtoArrayForkChoice = container.into();

    info!(log, "Fork choice length prior to prune"; "length"=> fork_choice.len());

    // Prune the fork choice as much as possible to reduce the chances of trying to load a missing
    // beacon state unnecessarily.
    fork_choice.set_prune_threshold(0);
    fork_choice.maybe_prune(finalized_checkpoint.root)?;
    fork_choice.set_prune_threshold(DEFAULT_PRUNE_THRESHOLD);

    info!(log, "Fork choice length after prune"; "length"=> fork_choice.len());

    update_checkpoints::<T>(
        finalized_checkpoint.root,
        &legacy_nodes,
        &mut fork_choice,
        db,
    )?;

    persisted_fork_choice.fork_choice.proto_array_bytes = fork_choice.as_bytes();

    Ok(())
}

struct HeadInfo {
    index: usize,
    root: Hash256,
    slot: Slot,
}

fn update_checkpoints<T: BeaconChainTypes>(
    finalized_root: Hash256,
    legacy_nodes: &[LegacyProtoNode],
    fork_choice: &mut ProtoArrayForkChoice,
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<(), String> {
    let heads = find_finalized_descendant_heads(finalized_root, fork_choice);

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

        // find the block roots associated with each relevant epoch.
        let roots_by_epoch = map_relevant_epochs_to_roots::<T>(
            head.root,
            head.slot,
            relevant_epochs.as_slice(),
            db.clone(),
            log.clone()
        )?;

        // Apply this mutator to the chain of descendants from this head, adding justified
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

/// Sorts and de-duplicates the given `epochs` and creates a single `BlockRootsIterator`. Iterates
/// backwards from the given `head_root` and `head_slot` and finds the block root at the start slot
/// of each epoch.
fn map_relevant_epochs_to_roots<T: BeaconChainTypes>(
    head_root: Hash256,
    head_slot: Slot,
    epochs: &[Epoch],
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<HashMap<Epoch, Hash256>, String> {
    // Remove duplicates and reverse sort the epochs.
    let mut relevant_epochs = epochs.into_iter().copied().unique().collect::<Vec<_>>();
    relevant_epochs.sort_unstable_by(|a, b| b.cmp(a));

    info!(log,"sorted and de-duped"; "relevant_epochs" => ?relevant_epochs);

    // Iterate backwards from the given `head_root` and `head_slot` and find the block root at each epoch.
    let mut iter = std::iter::once(Ok((head_root, head_slot)))
        .chain(BlockRootsIterator::from_block(db, head_root).map_err(|e| format!("{:?}", e))?);
    let mut roots_by_epoch = HashMap::new();
    for epoch in relevant_epochs.into_iter() {
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

/// Applies a mutator to every node in a chain for descendants from the `finalized_root`, starting
/// with the node at the given `head_index`.
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
/// check that these nodes are descendants of the finalized root in order to determine if they are
/// relevant.
fn find_finalized_descendant_heads(
    finalized_root: Hash256,
    fork_choice: &ProtoArrayForkChoice,
) -> Vec<HeadInfo> {
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

/// Only used for SSZ deserialization of the persisted fork choice during the database migration
/// from schema 5 to schema 6.
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
/// from schema 5 to schema 6.
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
