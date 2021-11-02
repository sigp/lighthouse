use crate::{
    proto_array::{ProtoArray, ProtoNode},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker},
};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use types::{Epoch, Hash256};

#[derive(Encode, Decode)]
pub struct SszContainer {
    pub votes: Vec<VoteTracker>,
    pub balances: Vec<u64>,
    pub prune_threshold: usize,
    pub justified_epoch: Epoch,
    pub finalized_epoch: Epoch,
    pub nodes: Vec<ProtoNode>,
    pub indices: Vec<(Hash256, usize)>,
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
            indices: from.indices.into_iter().collect::<HashMap<_, _>>(),
        };

        Self {
            proto_array,
            votes: ElasticList(from.votes),
            balances: from.balances,
        }
    }
}
