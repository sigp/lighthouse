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

use state_processing::{BlockProcessingError, ConsensusContext, envelope_processing::EnvelopeProcessingError};
use tracing::instrument;
use types::{BeaconState, BeaconStateError, ChainSpec, DataColumnSidecarList, EthSpec, ExecutionBlockHash, Hash256, SignedBeaconBlock, SignedExecutionPayloadEnvelope, Slot};

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, NotifyExecutionLayer, block_verification::PayloadVerificationHandle, payload_envelope_verification::gossip_verified_envelope::GossipVerifiedEnvelope};

pub mod execution_pending_envelope;
pub mod gossip_verified_envelope;
mod payload_notifier;

pub trait IntoExecutionPendingEnvelope<T: BeaconChainTypes>: Sized {
    fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T>, EnvelopeError>;
}

pub struct ExecutionPendingEnvelope<T: BeaconChainTypes> {
    pub signed_envelope: MaybeAvailableEnvelope<T::EthSpec>,
    pub import_data: EnvelopeImportData<T::EthSpec>,
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

#[derive(Debug, Clone)]
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
    // Some Beacon Chain Error
    BeaconChainError(Arc<BeaconChainError>),
    // Some Beacon State error
    BeaconStateError(BeaconStateError),
    // Some BlockProcessingError (for electra operations)
    BlockProcessingError(BlockProcessingError),
    // Some EnvelopeProcessingError
    EnvelopeProcessingError(EnvelopeProcessingError),
}

impl From<BeaconChainError> for EnvelopeError {
    fn from(e: BeaconChainError) -> Self {
        EnvelopeError::BeaconChainError(Arc::new(e))
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
) -> Result<EnvelopeProcessingSnapshot<T::EthSpec>, EnvelopeError> {
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
        return Err(EnvelopeError::BlockRootUnknown {
            block_root: beacon_block_root,
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
        .map_err(|e| EnvelopeError::BeaconChainError(Arc::new(e.into())))?
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
    ) -> Result<ExecutionPendingEnvelope<T>, EnvelopeError> {
        // TODO(EIP-7732): figure out how this should be refactored..
        GossipVerifiedEnvelope::new(self, chain)?
            .into_execution_pending_envelope(chain, notify_execution_layer)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PayloadEnvelopeImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub state: BeaconState<E>,
    pub consensus_context: ConsensusContext<E>,
}
