//! The incremental processing steps (e.g., signatures verified but not the state transition) is
//! represented as a sequence of wrapper-types around the block. There is a linear progression of
//! types, starting at a `SignedBeaconBlock` and finishing with a `Fully VerifiedBlock` (see
//! diagram below).
//!
//! ```ignore
//!            START
//!              |
//!              ▼
//! SignedExecutionPayloadEnvelope
//!              |
//!              |---------------
//!              |              |
//!              |              ▼
//!              |    GossipVerifiedEnvelope
//!              |              |
//!              |---------------
//!              |
//!              ▼
//!  ExecutionPendingEnvelope
//!              |
//!            await
//!              |
//!              ▼
//!             END
//!
//! ```

use std::sync::Arc;

use state_processing::{
    BlockProcessingError, ConsensusContext, envelope_processing::EnvelopeProcessingError,
};
use tracing::instrument;
use types::{
    BeaconState, BeaconStateError, ChainSpec, DataColumnSidecarList, EthSpec, ExecutionBlockHash,
    ExecutionPayloadEnvelope, Hash256, SignedBeaconBlock, SignedExecutionPayloadEnvelope, Slot,
};

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockError, ExecutionPayloadError,
    NotifyExecutionLayer, PayloadVerificationOutcome,
    block_verification::PayloadVerificationHandle,
    payload_envelope_verification::gossip_verified_envelope::GossipVerifiedEnvelope,
};

pub mod gossip_verified_envelope;
mod payload_notifier;
mod tests;

pub trait IntoExecutionPendingEnvelope<T: BeaconChainTypes>: Sized {
    fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T::EthSpec>, BlockError>;

    fn envelope(&self) -> &Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>;
}

pub struct ExecutionPendingEnvelope<E: EthSpec> {
    pub signed_envelope: MaybeAvailableEnvelope<E>,
    pub import_data: EnvelopeImportData<E>,
    pub payload_verification_handle: PayloadVerificationHandle,
}

#[derive(PartialEq)]
pub struct EnvelopeImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub block: Arc<SignedBeaconBlock<E>>,
    pub post_state: Box<BeaconState<E>>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct AvailableEnvelope<E: EthSpec> {
    // TODO(EIP-7732): rename to execution_block_hash
    block_hash: ExecutionBlockHash,
    envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
    columns: DataColumnSidecarList<E>,
    /// Timestamp at which this block first became available (UNIX timestamp, time since 1970).
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

/// This snapshot is to be used for verifying a envelope of the block.
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
/// 1. `Available`: This enelope has been executed and also contains all data to consider it
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
    BlockRootUnknown {
        block_root: Hash256,
    },
    /// The signature is invalid.
    BadSignature,
    /// The builder index doesn't match the committed bid
    BuilderIndexMismatch {
        committed_bid: u64,
        envelope: u64,
    },
    // The envelope slot doesn't match the block
    SlotMismatch {
        block: Slot,
        envelope: Slot,
    },
    // The validator index is unknown
    UnknownValidator {
        builder_index: u64,
    },
    // The block hash doesn't match the committed bid
    BlockHashMismatch {
        committed_bid: ExecutionBlockHash,
        envelope: ExecutionBlockHash,
    },
    // The slot belongs to a block that is from a slot prior than
    // the most recently finalized slot
    PriorToFinalization {
        payload_slot: Slot,
        latest_finalized_slot: Slot,
    },
    // Some Beacon Chain Error
    BeaconChainError(Arc<BeaconChainError>),
    // Some Beacon State error
    BeaconStateError(BeaconStateError),
    // Some BlockProcessingError (for electra operations)
    BlockProcessingError(BlockProcessingError),
    // Some EnvelopeProcessingError
    EnvelopeProcessingError(EnvelopeProcessingError),
    // Error verifying the execution payload
    ExecutionPayloadError(ExecutionPayloadError),
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

#[allow(clippy::type_complexity)]
#[instrument(skip_all, level = "debug", fields(beacon_block_root = %envelope.beacon_block_root()))]
pub(crate) fn load_snapshot<T: BeaconChainTypes>(
    envelope: &SignedExecutionPayloadEnvelope<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<EnvelopeProcessingSnapshot<T::EthSpec>, BlockError> {
    // Reject any block if its block is not known to fork choice.
    //
    // A block that is not in fork choice is either:
    //
    //  - Not yet imported: we should reject this block because we should only import a child
    //  envelope after its parent has been fully imported.
    //  - Pre-finalized: if the block is _prior_ to finalization, we should ignore the envelope
    //  because it will revert finalization. Note that the finalized block is stored in fork
    //  choice, so we will not reject any child of the finalized block (this is relevant during
    //  genesis).

    let fork_choice_read_lock = chain.canonical_head.fork_choice_read_lock();
    let beacon_block_root = envelope.beacon_block_root();
    let Some(proto_beacon_block) = fork_choice_read_lock.get_block(&beacon_block_root) else {
        return Err(BlockError::ParentUnknown {
            parent_root: beacon_block_root,
        });
    };
    drop(fork_choice_read_lock);

    // TODO(EIP-7732): add metrics here

    let block_state_root = proto_beacon_block.state_root;
    // We can use `get_hot_state` here rather than `get_advanced_hot_state` because the envelope
    // must be from the same slot as its block (so no advance is required).
    let cache_state = true;
    let state = chain
        .store
        .get_hot_state(&block_state_root, cache_state)
        .map_err(|e| BlockError::BeaconChainError(Box::new(e.into())))?
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

impl<T: BeaconChainTypes> IntoExecutionPendingEnvelope<T>
    for Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>
{
    fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T::EthSpec>, BlockError> {
        // TODO(EIP-7732): figure out how this should be refactored..
        GossipVerifiedEnvelope::new(self, chain)?
            .into_execution_pending_envelope(chain, notify_execution_layer)
    }

    fn envelope(&self) -> &Arc<SignedExecutionPayloadEnvelope<T::EthSpec>> {
        self
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PayloadEnvelopeImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub state: BeaconState<E>,
    pub consensus_context: ConsensusContext<E>,
}
