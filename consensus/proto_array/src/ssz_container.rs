use crate::proto_array::ProposerBoost;
use crate::{
    proto_array::{ProtoArray, ProtoNodeV16, ProtoNodeV17},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker},
    Error, JustifiedBalances,
};
use ssz::{four_byte_option_impl, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::convert::TryFrom;
use superstruct::superstruct;
use types::{Checkpoint, Hash256};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

pub type SszContainer = SszContainerV17;

#[superstruct(
    variants(V16, V17),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
pub struct SszContainer {
    pub votes: Vec<VoteTracker>,
    pub balances: Vec<u64>,
    pub prune_threshold: usize,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    #[superstruct(only(V16))]
    pub nodes: Vec<ProtoNodeV16>,
    #[superstruct(only(V17))]
    pub nodes: Vec<ProtoNodeV17>,
    pub indices: Vec<(Hash256, usize)>,
    pub previous_proposer_boost: ProposerBoost,
}

impl TryInto<SszContainer> for SszContainerV16 {
    type Error = Error;

    fn try_into(self) -> Result<SszContainer, Error> {
        let nodes: Result<Vec<ProtoNodeV17>, Error> =
            self.nodes.into_iter().map(TryInto::try_into).collect();

        Ok(SszContainer {
            votes: self.votes,
            balances: self.balances,
            prune_threshold: self.prune_threshold,
            justified_checkpoint: self.justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,
            nodes: nodes?,
            indices: self.indices,
            previous_proposer_boost: self.previous_proposer_boost,
        })
    }
}

impl Into<SszContainerV16> for SszContainer {
    fn into(self) -> SszContainerV16 {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainerV16 {
            votes: self.votes,
            balances: self.balances,
            prune_threshold: self.prune_threshold,
            justified_checkpoint: self.justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,
            nodes,
            indices: self.indices,
            previous_proposer_boost: self.previous_proposer_boost,
        }
    }
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
