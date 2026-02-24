use crate::proto_array::ProposerBoost;
use crate::{
    Error, JustifiedBalances,
    proto_array::{ProtoArray, ProtoNode, ProtoNodeV17},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker},
};
use ssz::{Encode, four_byte_option_impl};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use superstruct::superstruct;
use types::{Checkpoint, Hash256};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

pub type SszContainer = SszContainerV29;

// Legacy containers (V17/V28) for backward compatibility with older schema versions.
#[superstruct(
    variants(V17, V28),
    variant_attributes(derive(Encode, Decode, Clone)),
    no_enum
)]
pub struct SszContainerLegacy {
    pub votes: Vec<VoteTracker>,
    #[superstruct(only(V17))]
    pub balances: Vec<u64>,
    pub prune_threshold: usize,
    // Deprecated, remove in a future schema migration
    justified_checkpoint: Checkpoint,
    // Deprecated, remove in a future schema migration
    finalized_checkpoint: Checkpoint,
    pub nodes: Vec<ProtoNodeV17>,
    pub indices: Vec<(Hash256, usize)>,
    pub previous_proposer_boost: ProposerBoost,
}

/// Current container version. Uses union-encoded `ProtoNode` to support mixed V17/V29 nodes.
#[derive(Encode, Decode, Clone)]
pub struct SszContainerV29 {
    pub votes: Vec<VoteTracker>,
    pub prune_threshold: usize,
    // Deprecated, remove in a future schema migration
    justified_checkpoint: Checkpoint,
    // Deprecated, remove in a future schema migration
    finalized_checkpoint: Checkpoint,
    pub nodes: Vec<ProtoNode>,
    pub indices: Vec<(Hash256, usize)>,
    pub previous_proposer_boost: ProposerBoost,
}

impl SszContainerV29 {
    pub fn from_proto_array(
        from: &ProtoArrayForkChoice,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
    ) -> Self {
        let proto_array = &from.proto_array;

        Self {
            votes: from.votes.0.clone(),
            prune_threshold: proto_array.prune_threshold,
            justified_checkpoint,
            finalized_checkpoint,
            nodes: proto_array.nodes.clone(),
            indices: proto_array.indices.iter().map(|(k, v)| (*k, *v)).collect(),
            previous_proposer_boost: proto_array.previous_proposer_boost,
        }
    }
}

impl TryFrom<(SszContainerV29, JustifiedBalances)> for ProtoArrayForkChoice {
    type Error = Error;

    fn try_from((from, balances): (SszContainerV29, JustifiedBalances)) -> Result<Self, Error> {
        let proto_array = ProtoArray {
            prune_threshold: from.prune_threshold,
            nodes: from.nodes,
            indices: from.indices.into_iter().collect::<HashMap<_, _>>(),
            previous_proposer_boost: from.previous_proposer_boost,
        };

        Ok(Self {
            proto_array,
            votes: ElasticList(from.votes),
            balances,
        })
    }
}

// Convert legacy V17 to V28 by dropping balances.
impl From<SszContainerLegacyV17> for SszContainerLegacyV28 {
    fn from(v17: SszContainerLegacyV17) -> Self {
        Self {
            votes: v17.votes,
            prune_threshold: v17.prune_threshold,
            justified_checkpoint: v17.justified_checkpoint,
            finalized_checkpoint: v17.finalized_checkpoint,
            nodes: v17.nodes,
            indices: v17.indices,
            previous_proposer_boost: v17.previous_proposer_boost,
        }
    }
}

// Convert legacy V28 to V17 by re-adding balances.
impl From<(SszContainerLegacyV28, JustifiedBalances)> for SszContainerLegacyV17 {
    fn from((v28, balances): (SszContainerLegacyV28, JustifiedBalances)) -> Self {
        Self {
            votes: v28.votes,
            balances: balances.effective_balances.clone(),
            prune_threshold: v28.prune_threshold,
            justified_checkpoint: v28.justified_checkpoint,
            finalized_checkpoint: v28.finalized_checkpoint,
            nodes: v28.nodes,
            indices: v28.indices,
            previous_proposer_boost: v28.previous_proposer_boost,
        }
    }
}

// Convert legacy V28 to current V29.
impl From<SszContainerLegacyV28> for SszContainerV29 {
    fn from(v28: SszContainerLegacyV28) -> Self {
        Self {
            votes: v28.votes,
            prune_threshold: v28.prune_threshold,
            justified_checkpoint: v28.justified_checkpoint,
            finalized_checkpoint: v28.finalized_checkpoint,
            nodes: v28.nodes.into_iter().map(ProtoNode::V17).collect(),
            indices: v28.indices,
            previous_proposer_boost: v28.previous_proposer_boost,
        }
    }
}

// Downgrade current V29 to legacy V28 (lossy: V29 nodes lose payload-specific fields).
impl From<SszContainerV29> for SszContainerLegacyV28 {
    fn from(v29: SszContainerV29) -> Self {
        Self {
            votes: v29.votes,
            prune_threshold: v29.prune_threshold,
            justified_checkpoint: v29.justified_checkpoint,
            finalized_checkpoint: v29.finalized_checkpoint,
            nodes: v29
                .nodes
                .into_iter()
                .filter_map(|node| match node {
                    ProtoNode::V17(v17) => Some(v17),
                    ProtoNode::V29(_) => None,
                })
                .collect(),
            indices: v29.indices,
            previous_proposer_boost: v29.previous_proposer_boost,
        }
    }
}
