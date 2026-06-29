use crate::proto_array::ProposerBoost;
use crate::{
    Error, JustifiedBalances,
    proto_array::{ProtoArray, ProtoNode, ProtoNodeV17},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker, VoteTrackerV28},
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

#[superstruct(
    variants(V28, V29),
    variant_attributes(derive(Encode, Decode, Clone)),
    no_enum
)]
pub struct SszContainer {
    #[superstruct(only(V28))]
    pub votes_v28: Vec<VoteTrackerV28>,
    #[superstruct(only(V29))]
    pub votes: Vec<VoteTracker>,
    pub prune_threshold: usize,
    // Deprecated, remove in a future schema migration
    #[superstruct(only(V28))]
    justified_checkpoint: Checkpoint,
    // Deprecated, remove in a future schema migration
    #[superstruct(only(V28))]
    finalized_checkpoint: Checkpoint,
    #[superstruct(only(V28))]
    pub nodes: Vec<ProtoNodeV17>,
    #[superstruct(only(V29))]
    pub nodes: Vec<ProtoNode>,
    pub indices: Vec<(Hash256, usize)>,
    #[superstruct(only(V28))]
    pub previous_proposer_boost: ProposerBoost,
}

impl SszContainerV29 {
    pub fn from_proto_array(from: &ProtoArrayForkChoice) -> Self {
        let proto_array = &from.proto_array;

        Self {
            votes: from.votes.0.clone(),
            prune_threshold: proto_array.prune_threshold,
            nodes: proto_array.nodes.clone(),
            indices: proto_array.indices.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }
}

impl TryFrom<(SszContainerV29, JustifiedBalances)> for ProtoArrayForkChoice {
    type Error = Error;

    fn try_from((from, balances): (SszContainerV29, JustifiedBalances)) -> Result<Self, Error> {
        let mut proto_array = ProtoArray {
            prune_threshold: from.prune_threshold,
            nodes: from.nodes,
            indices: from.indices.into_iter().collect::<HashMap<_, _>>(),
            children: Vec::new(),
        };
        proto_array.rebuild_children_index()?;

        Ok(Self {
            proto_array,
            votes: ElasticList(from.votes),
            balances,
        })
    }
}

// Convert legacy V28 to current V29.
impl From<SszContainerV28> for SszContainerV29 {
    fn from(v28: SszContainerV28) -> Self {
        Self {
            votes: v28.votes_v28.into_iter().map(Into::into).collect(),
            prune_threshold: v28.prune_threshold,
            nodes: v28
                .nodes
                .into_iter()
                .map(|mut node| {
                    // best_child/best_descendant are no longer used (replaced by
                    // the virtual tree walk). Clear during conversion.
                    node.best_child = None;
                    node.best_descendant = None;
                    ProtoNode::V17(node)
                })
                .collect(),
            indices: v28.indices,
        }
    }
}

// Downgrade current V29 to legacy V28 (lossy: V29 nodes lose payload-specific fields).
impl From<SszContainerV29> for SszContainerV28 {
    fn from(v29: SszContainerV29) -> Self {
        Self {
            votes_v28: v29.votes.into_iter().map(Into::into).collect(),
            prune_threshold: v29.prune_threshold,
            // These checkpoints are not consumed in v28 paths since the upgrade from v17,
            // we can safely default the values.
            justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            nodes: v29
                .nodes
                .into_iter()
                .filter_map(|node| match node {
                    ProtoNode::V17(v17) => Some(v17),
                    ProtoNode::V29(_) => None,
                })
                .collect(),
            indices: v29.indices,
            // Proposer boost is not tracked in V29 (computed on-the-fly), so reset it.
            previous_proposer_boost: ProposerBoost::default(),
        }
    }
}
