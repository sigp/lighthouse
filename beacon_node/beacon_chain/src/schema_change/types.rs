use crate::types::{AttestationShufflingId, Checkpoint, Epoch, Hash256, Slot};
use proto_array::core::{ProposerBoost, ProtoNode, SszContainer, VoteTracker};
use proto_array::ExecutionStatus;
use ssz::four_byte_option_impl;
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

#[superstruct(
    variants(V1, V6, V7, V10),
    variant_attributes(derive(Clone, PartialEq, Debug, Encode, Decode)),
    no_enum
)]
pub struct ProtoNode {
    pub slot: Slot,
    pub state_root: Hash256,
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub root: Hash256,
    #[ssz(with = "four_byte_option_usize")]
    pub parent: Option<usize>,
    #[superstruct(only(V1, V6))]
    pub justified_epoch: Epoch,
    #[superstruct(only(V1, V6))]
    pub finalized_epoch: Epoch,
    #[ssz(with = "four_byte_option_checkpoint")]
    #[superstruct(only(V7, V10))]
    pub justified_checkpoint: Option<Checkpoint>,
    #[ssz(with = "four_byte_option_checkpoint")]
    #[superstruct(only(V7, V10))]
    pub finalized_checkpoint: Option<Checkpoint>,
    pub weight: u64,
    #[ssz(with = "four_byte_option_usize")]
    pub best_child: Option<usize>,
    #[ssz(with = "four_byte_option_usize")]
    pub best_descendant: Option<usize>,
    #[superstruct(only(V6, V7, V10))]
    pub execution_status: ExecutionStatus,
    #[ssz(with = "four_byte_option_checkpoint")]
    #[superstruct(only(V10))]
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    #[ssz(with = "four_byte_option_checkpoint")]
    #[superstruct(only(V10))]
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,
}

impl Into<ProtoNodeV6> for ProtoNodeV1 {
    fn into(self) -> ProtoNodeV6 {
        ProtoNodeV6 {
            slot: self.slot,
            state_root: self.state_root,
            target_root: self.target_root,
            current_epoch_shuffling_id: self.current_epoch_shuffling_id,
            next_epoch_shuffling_id: self.next_epoch_shuffling_id,
            root: self.root,
            parent: self.parent,
            justified_epoch: self.justified_epoch,
            finalized_epoch: self.finalized_epoch,
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

impl Into<ProtoNodeV7> for ProtoNodeV6 {
    fn into(self) -> ProtoNodeV7 {
        ProtoNodeV7 {
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
            execution_status: self.execution_status,
        }
    }
}

impl Into<ProtoNodeV10> for ProtoNodeV7 {
    fn into(self) -> ProtoNodeV10 {
        ProtoNodeV10 {
            slot: self.slot,
            state_root: self.state_root,
            target_root: self.target_root,
            current_epoch_shuffling_id: self.current_epoch_shuffling_id,
            next_epoch_shuffling_id: self.next_epoch_shuffling_id,
            root: self.root,
            parent: self.parent,
            justified_checkpoint: self.justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,
            weight: self.weight,
            best_child: self.best_child,
            best_descendant: self.best_descendant,
            execution_status: self.execution_status,
            unrealized_justified_checkpoint: None,
            unrealized_finalized_checkpoint: None,
        }
    }
}

impl Into<ProtoNodeV7> for ProtoNodeV10 {
    fn into(self) -> ProtoNodeV7 {
        ProtoNodeV7 {
            slot: self.slot,
            state_root: self.state_root,
            target_root: self.target_root,
            current_epoch_shuffling_id: self.current_epoch_shuffling_id,
            next_epoch_shuffling_id: self.next_epoch_shuffling_id,
            root: self.root,
            parent: self.parent,
            justified_checkpoint: self.justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,
            weight: self.weight,
            best_child: self.best_child,
            best_descendant: self.best_descendant,
            execution_status: self.execution_status,
        }
    }
}

impl Into<ProtoNode> for ProtoNodeV10 {
    fn into(self) -> ProtoNode {
        ProtoNode {
            slot: self.slot,
            state_root: self.state_root,
            target_root: self.target_root,
            current_epoch_shuffling_id: self.current_epoch_shuffling_id,
            next_epoch_shuffling_id: self.next_epoch_shuffling_id,
            root: self.root,
            parent: self.parent,
            justified_checkpoint: self.justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,
            weight: self.weight,
            best_child: self.best_child,
            best_descendant: self.best_descendant,
            execution_status: self.execution_status,
            unrealized_justified_checkpoint: self.unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint: self.unrealized_finalized_checkpoint,
        }
    }
}

impl From<ProtoNode> for ProtoNodeV7 {
    fn from(container: ProtoNode) -> Self {
        Self {
            slot: container.slot,
            state_root: container.state_root,
            target_root: container.target_root,
            current_epoch_shuffling_id: container.current_epoch_shuffling_id,
            next_epoch_shuffling_id: container.next_epoch_shuffling_id,
            root: container.root,
            parent: container.parent,
            justified_checkpoint: container.justified_checkpoint,
            finalized_checkpoint: container.finalized_checkpoint,
            weight: container.weight,
            best_child: container.best_child,
            best_descendant: container.best_descendant,
            execution_status: container.execution_status,
        }
    }
}

#[superstruct(
    variants(V1, V6, V7, V10),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
#[derive(Encode, Decode)]
pub struct SszContainer {
    pub votes: Vec<VoteTracker>,
    pub balances: Vec<u64>,
    pub prune_threshold: usize,
    #[superstruct(only(V1, V6))]
    pub justified_epoch: Epoch,
    #[superstruct(only(V1, V6))]
    pub finalized_epoch: Epoch,
    #[superstruct(only(V7, V10))]
    pub justified_checkpoint: Checkpoint,
    #[superstruct(only(V7, V10))]
    pub finalized_checkpoint: Checkpoint,
    #[superstruct(only(V1))]
    pub nodes: Vec<ProtoNodeV1>,
    #[superstruct(only(V6))]
    pub nodes: Vec<ProtoNodeV6>,
    #[superstruct(only(V7))]
    pub nodes: Vec<ProtoNodeV7>,
    #[superstruct(only(V10))]
    pub nodes: Vec<ProtoNodeV10>,
    pub indices: Vec<(Hash256, usize)>,
    #[superstruct(only(V7, V10))]
    pub previous_proposer_boost: ProposerBoost,
}

impl Into<SszContainerV6> for SszContainerV1 {
    fn into(self) -> SszContainerV6 {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainerV6 {
            votes: self.votes,
            balances: self.balances,
            prune_threshold: self.prune_threshold,
            justified_epoch: self.justified_epoch,
            finalized_epoch: self.finalized_epoch,
            nodes,
            indices: self.indices,
        }
    }
}

impl SszContainerV6 {
    pub(crate) fn into_ssz_container_v7(
        self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
    ) -> SszContainerV7 {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainerV7 {
            votes: self.votes,
            balances: self.balances,
            prune_threshold: self.prune_threshold,
            justified_checkpoint,
            finalized_checkpoint,
            nodes,
            indices: self.indices,
            previous_proposer_boost: ProposerBoost::default(),
        }
    }
}

impl Into<SszContainerV10> for SszContainerV7 {
    fn into(self) -> SszContainerV10 {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainerV10 {
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

impl Into<SszContainerV7> for SszContainerV10 {
    fn into(self) -> SszContainerV7 {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainerV7 {
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

impl Into<SszContainer> for SszContainerV10 {
    fn into(self) -> SszContainer {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainer {
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

impl From<SszContainer> for SszContainerV7 {
    fn from(container: SszContainer) -> Self {
        let nodes = container.nodes.into_iter().map(Into::into).collect();

        Self {
            votes: container.votes,
            balances: container.balances,
            prune_threshold: container.prune_threshold,
            justified_checkpoint: container.justified_checkpoint,
            finalized_checkpoint: container.finalized_checkpoint,
            nodes,
            indices: container.indices,
            previous_proposer_boost: container.previous_proposer_boost,
        }
    }
}
