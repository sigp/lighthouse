//! Handlers for `GET debug/fork_choice`.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{
    ForkChoice, ForkChoiceExtraData, ForkChoiceExtraDataV2, ForkChoiceNode,
    ForkChoiceNodeExtraDataV2, ForkChoiceNodeV2, ForkChoiceV2,
};
use fixed_bytes::FixedBytesExtended;
use proto_array::core::ProtoNode;
use proto_array::{ParentPayloadStatus, PayloadBlockHash, PayloadStatus, ProtoArrayForkChoice};
use types::{ExecutionBlockHash, Hash256};
use warp::Rejection;

/// Handles `GET v1/debug/fork_choice`. Deprecated in favour of `fork_choice_v2`.
pub fn fork_choice_v1<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<ForkChoice, Rejection> {
    let beacon_fork_choice = chain.canonical_head.fork_choice_read_lock();

    let proto_array = beacon_fork_choice.proto_array().core_proto_array();

    let fork_choice_nodes = proto_array
        .nodes
        .iter()
        .map(|node| {
            let execution_status = node
                .execution_status()
                .is_execution_enabled()
                .then(|| node.execution_status().to_string());

            let execution_status_string = node.execution_status().to_string();

            ForkChoiceNode {
                slot: node.slot(),
                block_root: node.root(),
                parent_root: node
                    .parent()
                    .and_then(|index| proto_array.nodes.get(index))
                    .map(|parent| parent.root()),
                justified_epoch: node.justified_checkpoint().epoch,
                finalized_epoch: node.finalized_checkpoint().epoch,
                weight: node.weight(),
                validity: execution_status,
                execution_block_hash: match node.block_hash() {
                    PayloadBlockHash::Hash(block_hash) => Some(block_hash.into_root()),
                    PayloadBlockHash::PreMerge => None,
                },
                extra_data: ForkChoiceExtraData {
                    target_root: node.target_root(),
                    justified_root: node.justified_checkpoint().root,
                    finalized_root: node.finalized_checkpoint().root,
                    unrealized_justified_root: node
                        .unrealized_justified_checkpoint()
                        .map(|checkpoint| checkpoint.root),
                    unrealized_finalized_root: node
                        .unrealized_finalized_checkpoint()
                        .map(|checkpoint| checkpoint.root),
                    unrealized_justified_epoch: node
                        .unrealized_justified_checkpoint()
                        .map(|checkpoint| checkpoint.epoch),
                    unrealized_finalized_epoch: node
                        .unrealized_finalized_checkpoint()
                        .map(|checkpoint| checkpoint.epoch),
                    execution_status: execution_status_string,
                    best_child: node
                        .best_child()
                        .ok()
                        .flatten()
                        .and_then(|index| proto_array.nodes.get(index))
                        .map(|child| child.root()),
                    best_descendant: node
                        .best_descendant()
                        .ok()
                        .flatten()
                        .and_then(|index| proto_array.nodes.get(index))
                        .map(|descendant| descendant.root()),
                },
            }
        })
        .collect::<Vec<_>>();
    Ok(ForkChoice {
        justified_checkpoint: beacon_fork_choice.justified_checkpoint(),
        finalized_checkpoint: beacon_fork_choice.finalized_checkpoint(),
        fork_choice_nodes,
    })
}

/// Handles `GET v2/debug/fork_choice`, expanding each proto-array node into the spec's
/// `(block_root, payload_status)` nodes.
pub fn fork_choice_v2<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<ForkChoiceV2, Rejection> {
    // Read before taking the fork choice lock, so the two locks are never held together.
    let cached_head = chain.canonical_head.cached_head();

    let beacon_fork_choice = chain.canonical_head.fork_choice_read_lock();
    let proto_array_fork_choice = beacon_fork_choice.proto_array();

    let proto_array = proto_array_fork_choice.core_proto_array();

    let mut fork_choice_nodes = vec![];
    for node in &proto_array.nodes {
        push_fork_choice_nodes(node, proto_array_fork_choice, &mut fork_choice_nodes)?;
    }

    // Fork choice tracks a pre-Gloas head as `Empty`, but this response shows a pre-Gloas
    // block as a single `Full` node.
    let head_root = cached_head.head_block_root();
    let head_payload_status = match proto_array.get_block(head_root) {
        Some(ProtoNode::V17(_)) => PayloadStatus::Full,
        _ => cached_head.head_payload_status(),
    };

    Ok(ForkChoiceV2 {
        justified_checkpoint: beacon_fork_choice.justified_checkpoint(),
        finalized_checkpoint: beacon_fork_choice.finalized_checkpoint(),
        fork_choice_nodes,
        extra_data: ForkChoiceExtraDataV2 {
            head_root,
            head_payload_status,
            proposer_boost_root: beacon_fork_choice.proposer_boost_root(),
            unrealized_justified_checkpoint: beacon_fork_choice.unrealized_justified_checkpoint(),
            unrealized_finalized_checkpoint: beacon_fork_choice.unrealized_finalized_checkpoint(),
        },
    })
}

/// Pushes the fork choice nodes of `node`'s block onto `fork_choice_nodes`.
fn push_fork_choice_nodes(
    node: &ProtoNode,
    proto_array_fork_choice: &ProtoArrayForkChoice,
    fork_choice_nodes: &mut Vec<ForkChoiceNodeV2>,
) -> Result<(), Rejection> {
    let proto_array = proto_array_fork_choice.core_proto_array();
    let block_root = node.root();
    // `None` if pruned, giving a zero `parent_root`
    let parent_root = node
        .parent()
        .and_then(|index| proto_array.nodes.get(index))
        .map(|parent| parent.root());

    match node {
        ProtoNode::V17(_) => {
            let execution_block_hash = match node.block_hash() {
                PayloadBlockHash::Hash(block_hash) => block_hash,
                PayloadBlockHash::PreMerge => ExecutionBlockHash::zero(),
            };
            fork_choice_nodes.push(ForkChoiceNodeV2 {
                slot: node.slot(),
                block_root,
                payload_status: PayloadStatus::Full,
                parent_root: parent_root.unwrap_or_else(Hash256::zero),
                // A pre-Gloas parent is a single `Full` node.
                parent_payload_status: parent_root.map(|_| PayloadStatus::Full),
                justified_checkpoint: *node.justified_checkpoint(),
                finalized_checkpoint: *node.finalized_checkpoint(),
                weight: node.weight(),
                validity: proto_array_fork_choice
                    .get_block_execution_status_assuming_full(&block_root)
                    .map_err(warp_utils::reject::unhandled_error)?,
                execution_block_hash,
                payload_attester_count: 0,
                payload_availability_yes_count: 0,
                payload_data_availability_yes_count: 0,
                extra_data: ForkChoiceNodeExtraDataV2 {
                    target_root: node.target_root(),
                    state_root: node.state_root(),
                    unrealized_justified_checkpoint: node.unrealized_justified_checkpoint(),
                    unrealized_finalized_checkpoint: node.unrealized_finalized_checkpoint(),
                    execution_status: node.execution_status().to_string(),
                },
            });
        }
        ProtoNode::V29(gloas_node) => {
            let parent_payload_status =
                parent_root.map(|_| match gloas_node.parent_payload_status {
                    ParentPayloadStatus::Empty => PayloadStatus::Empty,
                    ParentPayloadStatus::Full | ParentPayloadStatus::PreGloas => {
                        PayloadStatus::Full
                    }
                });

            let pending = ForkChoiceNodeV2 {
                slot: node.slot(),
                block_root,
                payload_status: PayloadStatus::Pending,
                parent_root: parent_root.unwrap_or_else(Hash256::zero),
                parent_payload_status,
                justified_checkpoint: *node.justified_checkpoint(),
                finalized_checkpoint: *node.finalized_checkpoint(),
                weight: gloas_node.weight,
                // Walks up through `Empty` edges, so the cost grows with long
                // runs of missed payloads.
                validity: proto_array
                    .inherited_execution_status(block_root)
                    .map_err(warp_utils::reject::unhandled_error)?,
                execution_block_hash: gloas_node.execution_payload_parent_hash,
                payload_attester_count: gloas_node.ptc_participation.num_set_bits() as u64,
                payload_availability_yes_count: gloas_node.payload_timeliness_votes.num_set_bits()
                    as u64,
                payload_data_availability_yes_count: gloas_node
                    .payload_data_availability_votes
                    .num_set_bits() as u64,
                extra_data: ForkChoiceNodeExtraDataV2 {
                    target_root: node.target_root(),
                    state_root: node.state_root(),
                    unrealized_justified_checkpoint: node.unrealized_justified_checkpoint(),
                    unrealized_finalized_checkpoint: node.unrealized_finalized_checkpoint(),
                    execution_status: node.execution_status().to_string(),
                },
            };

            fork_choice_nodes.push(pending.clone());

            let empty = ForkChoiceNodeV2 {
                payload_status: PayloadStatus::Empty,
                parent_root: block_root,
                parent_payload_status: Some(PayloadStatus::Pending),
                weight: gloas_node.empty_payload_weight,
                ..pending
            };

            fork_choice_nodes.push(empty.clone());
            if gloas_node.payload_received {
                let full = ForkChoiceNodeV2 {
                    payload_status: PayloadStatus::Full,
                    weight: gloas_node.full_payload_weight,
                    validity: proto_array_fork_choice
                        .get_block_execution_status_assuming_full(&block_root)
                        .map_err(warp_utils::reject::unhandled_error)?,
                    execution_block_hash: gloas_node.execution_payload_block_hash,
                    ..empty
                };
                fork_choice_nodes.push(full);
            }
        }
    }

    Ok(())
}
