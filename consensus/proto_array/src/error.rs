use safe_arith::ArithError;
use types::{Checkpoint, Epoch, ExecutionBlockHash, Hash256, Slot};

#[derive(Clone, PartialEq, Debug)]
pub enum Error {
    FinalizedNodeUnknown(Hash256),
    JustifiedNodeUnknown(Hash256),
    NodeUnknown(Hash256),
    InvalidFinalizedRootChange,
    InvalidNodeIndex(usize),
    InvalidParentIndex(usize),
    InvalidBestChildIndex(usize),
    InvalidJustifiedIndex(usize),
    InvalidBestDescendant(usize),
    InvalidParentDelta(usize),
    InvalidNodeDelta(usize),
    DeltaOverflow(usize),
    ProposerBoostOverflow(usize),
    ReOrgThresholdOverflow,
    IndexOverflow(&'static str),
    InvalidExecutionDeltaOverflow(usize),
    InvalidDeltaLen {
        deltas: usize,
        indices: usize,
    },
    RevertedFinalizedEpoch {
        current_finalized_epoch: Epoch,
        new_finalized_epoch: Epoch,
    },
    InvalidBestNode(Box<InvalidBestNodeInfo>),
    InvalidAncestorOfValidPayload {
        ancestor_block_root: Hash256,
        ancestor_payload_block_hash: ExecutionBlockHash,
    },
    ValidExecutionStatusBecameInvalid {
        block_root: Hash256,
        payload_block_hash: ExecutionBlockHash,
    },
    InvalidJustifiedCheckpointExecutionStatus {
        justified_root: Hash256,
    },
    UnknownLatestValidAncestorHash {
        block_root: Hash256,
        latest_valid_ancestor_hash: Option<ExecutionBlockHash>,
    },
    IrrelevantDescendant {
        block_root: Hash256,
    },
    ParentExecutionStatusIsInvalid {
        block_root: Hash256,
        parent_root: Hash256,
    },
    Arith(ArithError),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::Arith(e)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct InvalidBestNodeInfo {
    pub current_slot: Slot,
    pub start_root: Hash256,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub head_root: Hash256,
    pub head_justified_checkpoint: Option<Checkpoint>,
    pub head_finalized_checkpoint: Option<Checkpoint>,
}
