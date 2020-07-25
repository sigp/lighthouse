use crate::{
    proto_array::{ProtoArray, ProtoNode},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker},
};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::iter::FromIterator;
use types::{Epoch, Hash256};

#[derive(Encode, Decode)]
pub struct SszContainer {
    votes: Vec<VoteTracker>,
    balances: Vec<u64>,
    prune_threshold: usize,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    nodes: Vec<ProtoNode>,
    indices: Vec<(Hash256, usize)>,
}

impl From<&ProtoArrayForkChoice> for SszContainer {
    fn from(from: &ProtoArrayForkChoice) -> Self {
        let proto_array = &from.proto_array;

        Self {
            votes: from.votes.0.clone(),
            balances: from.balances.clone(),
            prune_threshold: proto_array.prune_threshold,
            justified_epoch: proto_array.justified_epoch,
            finalized_epoch: proto_array.finalized_epoch,
            nodes: proto_array.nodes.clone(),
            indices: proto_array.indices.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }
}

impl From<SszContainer> for ProtoArrayForkChoice {
    fn from(from: SszContainer) -> Self {
        let proto_array = ProtoArray {
            prune_threshold: from.prune_threshold,
            justified_epoch: from.justified_epoch,
            finalized_epoch: from.finalized_epoch,
            nodes: from.nodes,
            indices: HashMap::from_iter(from.indices.into_iter()),
        };

        Self {
            proto_array,
            votes: ElasticList(from.votes),
            balances: from.balances,
        }
    }
}
