//! The incremental processing steps (e.g., signatures verified but not the state transition) is
//! represented as a sequence of wrapper-types around the envelope. There is a linear progression of
//! types, starting at a `SignedExecutionPayloadEnvelope` and finishing with an `AvailableExecutedEnvelope` (see
//! diagram below).
//!
//! ```ignore
//! SignedExecutionPayloadEnvelope
//!              |
//!              ▼
//!    GossipVerifiedEnvelope
//!              |
//!              ▼
//!  ExecutionPendingEnvelope
//!              |
//!            await
//!              ▼
//!      ExecutedEnvelope
//!
//! ```

use std::sync::Arc;

use store::Error as DBError;

use state_processing::{BlockProcessingError, envelope_processing::EnvelopeProcessingError};
use tracing::instrument;
use types::{
    BeaconState, BeaconStateError, ChainSpec, DataColumnSidecarList, EthSpec, ExecutionBlockHash,
    ExecutionPayloadEnvelope, Hash256, SignedExecutionPayloadEnvelope, Slot,
};

use crate::{
    BeaconChainError, BeaconChainTypes, BeaconStore, BlockError, ExecutionPayloadError,
    PayloadVerificationOutcome,
};

pub mod execution_pending_envelope;
pub mod gossip_verified_envelope;
pub mod import;
mod payload_notifier;

pub use execution_pending_envelope::ExecutionPendingEnvelope;

#[derive(PartialEq)]
pub struct EnvelopeImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub post_state: Box<BeaconState<E>>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct AvailableEnvelope<E: EthSpec> {
    execution_block_hash: ExecutionBlockHash,
    envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
    columns: DataColumnSidecarList<E>,
    /// Timestamp at which this envelope first became available (UNIX timestamp, time since 1970).
    columns_available_timestamp: Option<std::time::Duration>,
    pub spec: Arc<ChainSpec>,
}

impl<E: EthSpec> AvailableEnvelope<E> {
    pub fn message(&self) -> &ExecutionPayloadEnvelope<E> {
        &self.envelope.message
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(
        self,
    ) -> (
        Arc<SignedExecutionPayloadEnvelope<E>>,
        DataColumnSidecarList<E>,
    ) {
        let AvailableEnvelope {
            envelope, columns, ..
        } = self;
        (envelope, columns)
    }
}

pub enum MaybeAvailableEnvelope<E: EthSpec> {
    Available(AvailableEnvelope<E>),
    AvailabilityPending {
        block_hash: ExecutionBlockHash,
        envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
    },
}

/// This snapshot is to be used for verifying a payload envelope.
#[derive(Debug, Clone)]
pub struct EnvelopeProcessingSnapshot<E: EthSpec> {
    /// This state is equivalent to the `self.beacon_block.state_root()` before applying the envelope.
    pub pre_state: BeaconState<E>,
    pub state_root: Hash256,
    pub beacon_block_root: Hash256,
}

/// A payload envelope that has gone through processing checks and execution by an EL client.
/// This envelope hasn't necessarily completed data availability checks.
///
///
/// It contains 2 variants:
/// 1. `Available`: This envelope has been executed and also contains all data to consider it
///    fully available.
/// 2. `AvailabilityPending`: This envelope hasn't received all required blobs to consider it
///    fully available.
pub enum ExecutedEnvelope<E: EthSpec> {
    Available(AvailableExecutedEnvelope<E>),
    // TODO(gloas) implement availability pending
    AvailabilityPending(),
}

impl<E: EthSpec> ExecutedEnvelope<E> {
    pub fn new(
        envelope: MaybeAvailableEnvelope<E>,
        import_data: EnvelopeImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        match envelope {
            MaybeAvailableEnvelope::Available(available_envelope) => {
                Self::Available(AvailableExecutedEnvelope::new(
                    available_envelope,
                    import_data,
                    payload_verification_outcome,
                ))
            }
            // TODO(gloas) implement availability pending
            MaybeAvailableEnvelope::AvailabilityPending {
                block_hash: _,
                envelope: _,
            } => Self::AvailabilityPending(),
        }
    }
}

/// A payload envelope that has completed all payload processing checks including verification
/// by an EL client **and** has all requisite blob data to be imported into fork choice.
pub struct AvailableExecutedEnvelope<E: EthSpec> {
    pub envelope: AvailableEnvelope<E>,
    pub import_data: EnvelopeImportData<E>,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailableExecutedEnvelope<E> {
    pub fn new(
        envelope: AvailableEnvelope<E>,
        import_data: EnvelopeImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            envelope,
            import_data,
            payload_verification_outcome,
        }
    }
}

#[derive(Debug)]
pub enum EnvelopeError {
    /// The envelope's block root is unknown.
    BlockRootUnknown { block_root: Hash256 },
    /// The signature is invalid.
    BadSignature,
    /// The builder index doesn't match the committed bid
    BuilderIndexMismatch { committed_bid: u64, envelope: u64 },
    /// The envelope slot doesn't match the block
    SlotMismatch { block: Slot, envelope: Slot },
    /// The validator index is unknown
    UnknownValidator { proposer_index: u64 },
    /// The block hash doesn't match the committed bid
    BlockHashMismatch {
        committed_bid: ExecutionBlockHash,
        envelope: ExecutionBlockHash,
    },
    /// The block's proposer_index does not match the locally computed proposer
    IncorrectBlockProposer {
        proposer_index: u64,
        local_shuffling: u64,
    },
    /// The slot belongs to a block that is from a slot prior than
    /// to most recently finalized slot
    PriorToFinalization {
        payload_slot: Slot,
        latest_finalized_slot: Slot,
    },
    /// Some Beacon Chain Error
    BeaconChainError(Arc<BeaconChainError>),
    /// Some Beacon State error
    BeaconStateError(BeaconStateError),
    /// Some BlockProcessingError (for electra operations)
    BlockProcessingError(BlockProcessingError),
    /// Some EnvelopeProcessingError
    EnvelopeProcessingError(EnvelopeProcessingError),
    /// Error verifying the execution payload
    ExecutionPayloadError(ExecutionPayloadError),
    /// An error from block-level checks reused during envelope import
    BlockError(BlockError),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconChainError> for EnvelopeError {
    fn from(e: BeaconChainError) -> Self {
        EnvelopeError::BeaconChainError(Arc::new(e))
    }
}

impl From<ExecutionPayloadError> for EnvelopeError {
    fn from(e: ExecutionPayloadError) -> Self {
        EnvelopeError::ExecutionPayloadError(e)
    }
}

impl From<BeaconStateError> for EnvelopeError {
    fn from(e: BeaconStateError) -> Self {
        EnvelopeError::BeaconStateError(e)
    }
}

impl From<DBError> for EnvelopeError {
    fn from(e: DBError) -> Self {
        EnvelopeError::BeaconChainError(Arc::new(BeaconChainError::DBError(e)))
    }
}

impl From<BlockError> for EnvelopeError {
    fn from(e: BlockError) -> Self {
        EnvelopeError::BlockError(e)
    }
}

/// Pull errors up from EnvelopeProcessingError to EnvelopeError
impl From<EnvelopeProcessingError> for EnvelopeError {
    fn from(e: EnvelopeProcessingError) -> Self {
        match e {
            EnvelopeProcessingError::BadSignature => EnvelopeError::BadSignature,
            EnvelopeProcessingError::BeaconStateError(e) => EnvelopeError::BeaconStateError(e),
            EnvelopeProcessingError::BlockHashMismatch {
                committed_bid,
                envelope,
            } => EnvelopeError::BlockHashMismatch {
                committed_bid,
                envelope,
            },
            EnvelopeProcessingError::BlockProcessingError(e) => {
                EnvelopeError::BlockProcessingError(e)
            }
            e => EnvelopeError::EnvelopeProcessingError(e),
        }
    }
}

#[instrument(skip_all, level = "debug", fields(beacon_block_root = %beacon_block_root))]
/// Load state from store given a known state root and block root.
/// Use this when the proto block has already been looked up from fork choice.
pub(crate) fn load_snapshot_from_state_root<T: BeaconChainTypes>(
    beacon_block_root: Hash256,
    block_state_root: Hash256,
    store: &BeaconStore<T>,
) -> Result<EnvelopeProcessingSnapshot<T::EthSpec>, EnvelopeError> {
    // TODO(EIP-7732): add metrics here

    // We can use `get_hot_state` here rather than `get_advanced_hot_state` because the envelope
    // must be from the same slot as its block (so no advance is required).
    let cache_state = true;
    let state = store
        .get_hot_state(&block_state_root, cache_state)
        .map_err(EnvelopeError::from)?
        .ok_or_else(|| {
            BeaconChainError::DBInconsistent(format!(
                "Missing state for envelope block {block_state_root:?}",
            ))
        })?;

    Ok(EnvelopeProcessingSnapshot {
        pre_state: state,
        state_root: block_state_root,
        beacon_block_root,
    })
}
