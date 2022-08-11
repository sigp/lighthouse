use crate::core::{ProtoArray, ProtoNode};
use serde::Serialize;
use std::collections::HashSet;
use types::*;

#[derive(Debug, Serialize)]
pub struct Tip {
    /// The root of the block.
    pub root: Hash256,
    /// The slot of the block.
    pub slot: Slot,
    /// The epoch of the block.
    pub epoch: Epoch,
    /// The sum of the weight of this block and all its ancestors, back to the common ancestor of
    /// all tip blocks.
    pub unique_chain_weight: u64,
    /// The `unique_chain_weight` of this tip block divided by the `unique_chain_weight` of the
    /// heaviest tip block (which might not be this block).
    pub unique_chain_weight_divided_by_heaviest: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct RootSlot {
    /// The root of a block.
    pub root: Hash256,
    /// The slot of a block.
    pub slot: Slot,
}

#[derive(Debug, Serialize)]
pub struct ProtoAnalysis {
    /// The head root of proto array, based on the assumed values for the current slot and justified
    /// root. Is `None` if the head cannot be found.
    pub head_root: Option<Hash256>,
    /// The highest slot of any block in proto array.
    pub highest_observed_slot: Slot,
    /// The block root of the block with the highest slot that is a common ancestor of all blocks.
    pub highest_common_ancestor_root: Hash256,
    /// As above, but the slot of that block.
    pub highest_common_ancestor_slot: Slot,
    /// The justified checkpoint, as determined by finding the highest *realized* justified epoch in
    /// all blocks.
    pub assumed_justified_checkpoint: Checkpoint,
    /// As above, but for the justified checkpoint.
    pub assumed_finalized_checkpoint: Checkpoint,
    /// A summary of each tip of the chain.
    pub tip_summaries: Vec<Tip>,
    /// A list of each block and root in the chain, back to the highest common ancestor.
    pub chains: Vec<Vec<RootSlot>>,
}

impl ProtoAnalysis {
    pub fn new<E: EthSpec>(proto_array: &ProtoArray) -> Result<Self, String> {
        let highest_observed_slot = proto_array
            .nodes
            .iter()
            .map(|node| node.slot)
            .max()
            .ok_or("Proto array is empty")?;
        let finalized_checkpoint = guess_finalized_checkpoint(&proto_array)
            .ok_or("Unable to guess finalized checkpoint")?;
        let justified_checkpoint = guess_justified_checkpoint(&proto_array)
            .ok_or("Unable to guess justified checkpoint")?;
        let tip_nodes = get_tips(proto_array, finalized_checkpoint.root)?;
        let highest_common_ancestor = get_highest_common_ancestor(proto_array, &tip_nodes)?;
        let tip_summaries =
            get_tip_summaries::<E>(proto_array, &tip_nodes, highest_common_ancestor.root)?;
        let head_root = proto_array
            .find_head::<E>(&justified_checkpoint.root, highest_observed_slot)
            .ok();
        let chains = tip_nodes
            .iter()
            .map(|tip| get_chain(proto_array, tip.root, Some(highest_common_ancestor.root)))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .map(|chain| {
                chain
                    .into_iter()
                    .map(|node| RootSlot {
                        root: node.root,
                        slot: node.slot,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        Ok(Self {
            head_root,
            highest_observed_slot,
            highest_common_ancestor_root: highest_common_ancestor.root,
            highest_common_ancestor_slot: highest_common_ancestor.slot,
            assumed_justified_checkpoint: justified_checkpoint,
            assumed_finalized_checkpoint: finalized_checkpoint,
            tip_summaries,
            chains,
        })
    }
}

fn get_tip_summaries<E: EthSpec>(
    proto_array: &ProtoArray,
    tips: &HashSet<&ProtoNode>,
    highest_common_ancestor_root: Hash256,
) -> Result<Vec<Tip>, String> {
    let mut tip_summaries = tips
        .iter()
        .map(|node| {
            Ok(Tip {
                root: node.root,
                slot: node.slot,
                epoch: node.slot.epoch(E::slots_per_epoch()),
                unique_chain_weight: get_unique_chain_weight(
                    proto_array,
                    node.root,
                    highest_common_ancestor_root,
                )?,
                unique_chain_weight_divided_by_heaviest: None,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let greatest_weight = tip_summaries
        .iter()
        .map(|tip| tip.unique_chain_weight)
        .max()
        .ok_or("No tips found")?;

    for mut tip in &mut tip_summaries {
        let value = tip.unique_chain_weight as f64 / greatest_weight as f64;
        tip.unique_chain_weight_divided_by_heaviest = Some(value);
    }

    Ok(tip_summaries)
}

fn guess_justified_checkpoint(proto_array: &ProtoArray) -> Option<Checkpoint> {
    proto_array
        .nodes
        .iter()
        .filter_map(|node| node.justified_checkpoint)
        .max_by_key(|checkpoint| checkpoint.epoch)
}

fn guess_finalized_checkpoint(proto_array: &ProtoArray) -> Option<Checkpoint> {
    proto_array
        .nodes
        .iter()
        .filter_map(|node| node.finalized_checkpoint)
        .max_by_key(|checkpoint| checkpoint.epoch)
}

fn get_tips(
    proto_array: &ProtoArray,
    finalized_block_root: Hash256,
) -> Result<HashSet<&ProtoNode>, String> {
    let mut all: HashSet<&ProtoNode> = HashSet::default();
    let mut parents: HashSet<&ProtoNode> = HashSet::default();

    for node in proto_array.nodes.iter().rev() {
        if node.parent.is_none() && node.root != finalized_block_root {
            // Parent-less nodes must be either the finalized block, or conflict with finality.
            continue;
        }

        all.insert(node);

        if let Some(parent_index) = node.parent {
            let parent = proto_array.nodes.get(parent_index).ok_or_else(|| {
                format!(
                    "Missing
                    parent: {}",
                    parent_index
                )
            })?;
            parents.insert(parent);
        }

        // Any block earlier than the finalized block must be either finalized or conflicting.
        if node.root == finalized_block_root {
            break;
        }
    }

    Ok(all.difference(&parents).copied().collect())
}

fn get_chain(
    proto_array: &ProtoArray,
    tip_root: Hash256,
    common_ancestor_root: Option<Hash256>,
) -> Result<Vec<&ProtoNode>, String> {
    let mut root = tip_root;
    let mut chain = vec![];
    loop {
        let index = proto_array
            .indices
            .get(&root)
            .ok_or_else(|| format!("Root {:?} unknown", tip_root))?;
        let node = proto_array
            .nodes
            .get(*index)
            .ok_or_else(|| format!("Node index {} missing", index))?;
        chain.push(node);

        if let Some(parent_index) = node.parent {
            let parent_node = proto_array
                .nodes
                .get(parent_index)
                .ok_or_else(|| format!("Parent index {} missing", parent_index))?;
            root = parent_node.root;

            if common_ancestor_root.map_or(false, |common_ancestor| common_ancestor == root) {
                break;
            }
        } else {
            break;
        }
    }
    Ok(chain)
}

fn get_highest_common_ancestor<'a>(
    proto_array: &'a ProtoArray,
    tips: &HashSet<&'a ProtoNode>,
) -> Result<&'a ProtoNode, String> {
    get_common_ancestors(proto_array, tips)?
        .iter()
        .max_by_key(|node| node.slot)
        .copied()
        .ok_or_else(|| "No tips when determining highest common ancestor".into())
}

fn get_common_ancestors<'a>(
    proto_array: &'a ProtoArray,
    tips: &HashSet<&'a ProtoNode>,
) -> Result<HashSet<&'a ProtoNode>, String> {
    let chains: Vec<HashSet<&ProtoNode>> = tips
        .iter()
        .map(|tip| {
            get_chain(proto_array, tip.root, None).map(|chain| chain.iter().copied().collect())
        })
        .collect::<Result<_, _>>()?;

    let mut chains_iter = chains.into_iter();
    let intersection = chains_iter
        .next()
        .map(|chain| {
            chains_iter.fold(chain, |chain1, chain2| {
                chain1.intersection(&chain2).copied().collect()
            })
        })
        .ok_or("No tips found when determining common ancestors")?;

    Ok(intersection)
}

fn get_unique_chain_weight(
    proto_array: &ProtoArray,
    tip_root: Hash256,
    common_ancestor: Hash256,
) -> Result<u64, String> {
    let tip_index = proto_array
        .indices
        .get(&tip_root)
        .ok_or_else(|| format!("Tip root {:?} unknown", tip_root))?;

    let mut node = proto_array
        .nodes
        .get(*tip_index)
        .ok_or_else(|| format!("Tip index {} missing", tip_index))?;

    let mut weight = 0;
    loop {
        weight += node.weight;
        if let Some(parent_index) = node.parent {
            node = proto_array
                .nodes
                .get(parent_index)
                .ok_or_else(|| format!("Parent index {} missing", parent_index))?;

            if node.root == common_ancestor {
                break;
            }
        } else {
            return Err("Reached finalized checkpoint before finding the common ancestor".into());
        }
    }

    Ok(weight)
}
