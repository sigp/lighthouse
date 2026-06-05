use crate::PayloadStatus;
use safe_arith::ArithError;
use types::{Epoch, ExecutionBlockHash, Hash256};

#[derive(Clone, PartialEq, Debug)]
pub enum Error {
    FinalizedNodeUnknown(Hash256),
    JustifiedNodeUnknown(Hash256),
    NodeUnknown(Hash256),
    InvalidFinalizedRootChange,
    InvalidNodeIndex(usize),
    InvalidJustifiedIndex(usize),
    InvalidBestDescendant(usize),
    InvalidParentDelta(usize),
    InvalidNodeDelta(usize),
    MissingJustifiedCheckpoint,
    MissingFinalizedCheckpoint,
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
    InvalidEpochOffset(u64),
    Arith(ArithError),
    InvalidNodeVariant {
        block_root: Hash256,
    },
    BrokenBlock {
        block_root: Hash256,
    },
    NoViableChildren,
    OnBlockRequiresProposerIndex,
    InvalidPayloadStatus {
        block_root: Hash256,
        payload_status: PayloadStatus,
    },
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::Arith(e)
    }
}
