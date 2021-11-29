use crate::persisted_fork_choice::PersistedForkChoice;
use crate::types::{AttestationShufflingId, Checkpoint, Epoch, Hash256, Slot};
use crate::BeaconChainTypes;

///! These functions and structs are only relevant to the database migration from schema 5 to 6.
use proto_array::core::{ProtoNode, SszContainer, VoteTracker};
use proto_array::ExecutionStatus;
use ssz::four_byte_option_impl;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);

pub(crate) fn update_execution_statuses<T: BeaconChainTypes>(
    persisted_fork_choice: &mut PersistedForkChoice,
) -> Result<(), String> {
    let legacy_container =
        LegacySszContainer::from_ssz_bytes(&persisted_fork_choice.fork_choice.proto_array_bytes)
            .map_err(|e| {
                format!(
                    "Failed to decode ProtoArrayForkChoice during schema migration: {:?}",
                    e
                )
            })?;

    let container: SszContainerSchema5 = legacy_container.into();

    persisted_fork_choice.fork_choice.proto_array_bytes = container.as_ssz_bytes();
    Ok(())
}

#[derive(Encode, Decode)]
pub(crate) struct LegacySszContainer {
    votes: Vec<VoteTracker>,
    balances: Vec<u64>,
    prune_threshold: usize,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    pub nodes: Vec<LegacyProtoNode>,
    indices: Vec<(Hash256, usize)>,
}
impl Into<SszContainerSchema5> for LegacySszContainer {
    fn into(self) -> SszContainerSchema5 {
        let nodes = self.nodes.into_iter().map(Into::into).collect();

        SszContainerSchema5 {
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

#[derive(Encode, Decode, Clone)]
pub(crate) struct LegacyProtoNode {
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

impl Into<ProtoNodeSchema5> for LegacyProtoNode {
    fn into(self) -> ProtoNodeSchema5 {
        ProtoNodeSchema5 {
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

#[derive(Encode, Decode)]
pub(crate) struct SszContainerSchema5 {
    votes: Vec<VoteTracker>,
    balances: Vec<u64>,
    prune_threshold: usize,
    justified_epoch: Epoch,
    finalized_epoch: Epoch,
    pub nodes: Vec<ProtoNodeSchema5>,
    indices: Vec<(Hash256, usize)>,
}

impl SszContainerSchema5 {
    pub(crate) fn into_ssz_container(
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

#[derive(Encode, Decode, Clone)]
pub(crate) struct ProtoNodeSchema5 {
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
    pub execution_status: ExecutionStatus,
}

impl Into<ProtoNode> for ProtoNodeSchema5 {
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
            execution_status: self.execution_status,
        }
    }
}
