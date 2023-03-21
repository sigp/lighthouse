use crate::proto_array::ProposerBoost;
use crate::{
    proto_array::{ProtoArray, ProtoNode},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker},
    Error, JustifiedBalances,
};
use ssz::{four_byte_option_impl, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::convert::TryFrom;
use types::{Checkpoint, Hash256};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

#[derive(Encode, Decode)]
pub struct SszContainer {
    pub votes: Vec<VoteTracker>,
    pub balances: Vec<u64>,
    pub prune_threshold: usize,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub nodes: Vec<ProtoNode>,
    pub indices: Vec<(Hash256, usize)>,
    pub previous_proposer_boost: ProposerBoost,
}

impl From<&ProtoArrayForkChoice> for SszContainer {
    fn from(from: &ProtoArrayForkChoice) -> Self {
        let proto_array = &from.proto_array;

        Self {
            votes: from.votes.0.clone(),
            balances: from.balances.effective_balances.clone(),
            prune_threshold: proto_array.prune_threshold,
            justified_checkpoint: proto_array.justified_checkpoint,
            finalized_checkpoint: proto_array.finalized_checkpoint,
            nodes: proto_array.nodes.clone(),
            indices: proto_array.indices.iter().map(|(k, v)| (*k, *v)).collect(),
            previous_proposer_boost: proto_array.previous_proposer_boost,
        }
    }
}

impl TryFrom<SszContainer> for ProtoArrayForkChoice {
    type Error = Error;

    fn try_from(from: SszContainer) -> Result<Self, Error> {
        let proto_array = ProtoArray {
            prune_threshold: from.prune_threshold,
            justified_checkpoint: from.justified_checkpoint,
            finalized_checkpoint: from.finalized_checkpoint,
            nodes: from.nodes,
            indices: from.indices.into_iter().collect::<HashMap<_, _>>(),
            previous_proposer_boost: from.previous_proposer_boost,
        };

        Ok(Self {
            proto_array,
            votes: ElasticList(from.votes),
            balances: JustifiedBalances::from_effective_balances(from.balances)?,
        })
    }
}
