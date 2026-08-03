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
use crate::data_availability_checker::AvailabilityCheckError;
use crate::{
    BeaconChainError, BeaconChainTypes, BeaconStore, BlockError, CustodyContext,
    ExecutionPayloadError, PayloadVerificationError, PayloadVerificationOutcome,
};
use state_processing::envelope_processing::EnvelopeProcessingError;
use std::collections::HashSet;
use std::sync::Arc;
use store::Error as DBError;
use strum::AsRefStr;
use tracing::{instrument, warn};
use types::{
    BeaconState, BeaconStateError, DataColumnSidecarList, EthSpec, ExecutionBlockHash,
    ExecutionPayloadEnvelope, Hash256, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
    Slot,
};

pub mod execution_pending_envelope;
pub mod gossip_verified_envelope;
pub mod import;
mod payload_notifier;

pub use execution_pending_envelope::ExecutionPendingEnvelope;

#[derive(Debug, Clone)]
pub struct AvailableEnvelope<E: EthSpec> {
    envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
    pub columns: DataColumnSidecarList<E>,
}

impl<E: EthSpec> AvailableEnvelope<E> {
    /// Constructs an `AvailableEnvelope` from an envelope and custody column data.
    ///
    /// This function validates that:
    /// - All required custody columns are present
    ///
    /// If more columns are provided than necessary, a warning is logged and the extra
    /// columns are filtered out of the list.
    ///
    /// Returns `AvailabilityCheckError` if:
    /// - `MissingCustodyColumns`: Required custody columns are missing or incomplete
    pub fn new<T>(
        envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
        columns: DataColumnSidecarList<E>,
        bid: &SignedExecutionPayloadBid<E>,
        custody_context: &CustodyContext<T>,
    ) -> Result<Self, AvailabilityCheckError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        if custody_context.data_columns_required_for_bid(bid) {
            let columns_expected = custody_context.num_of_data_columns_to_sample(bid.epoch());

            // Get required custody column indices
            let required_indices = custody_context
                .sampling_columns_for_epoch(bid.epoch())
                .iter()
                .copied()
                .collect::<HashSet<_>>();

            // Filter to only the columns we need (deduplicates if there are duplicates)
            let mut filtered_columns = Vec::new();
            let mut seen_indices = HashSet::new();
            let num_provided_columns = columns.len();
            for column in columns {
                if required_indices.contains(column.index()) && seen_indices.insert(*column.index())
                {
                    filtered_columns.push(column);
                }
            }

            // Check if we have all required columns
            if filtered_columns.len() != columns_expected {
                return Err(AvailabilityCheckError::MissingCustodyColumns);
            }

            if num_provided_columns != filtered_columns.len() {
                warn!(
                    message = "More columns provided than expected",
                    envelope = %envelope.message.payload.block_hash,
                    num_provided_columns = %num_provided_columns,
                    columns_expected = %columns_expected,
                );
            }

            Ok(Self {
                envelope,
                columns: filtered_columns,
            })
        } else if columns.is_empty() {
            Ok(Self { envelope, columns })
        } else {
            warn!(
                message = "Custody columns provided for envelope that does not require them",
                envelope = %envelope.message.payload.block_hash,
            );
            Ok(Self {
                envelope,
                columns: vec![],
            })
        }
    }

    pub fn envelope(&self) -> &Arc<SignedExecutionPayloadEnvelope<E>> {
        &self.envelope
    }

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

/// This snapshot is to be used for verifying a payload envelope.
#[derive(Debug, Clone)]
pub struct EnvelopeProcessingSnapshot<E: EthSpec> {
    /// This state is equivalent to the `self.beacon_block.state_root()` before applying the envelope.
    pub pre_state: BeaconState<E>,
    pub state_root: Hash256,
    pub beacon_block_root: Hash256,
}

/// A payload envelope that has completed all envelope processing checks, verification
/// by an EL client but does not have all requisite columns to get imported into
/// fork choice.
pub struct AvailabilityPendingExecutedEnvelope<E: EthSpec> {
    pub envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
    pub block_root: Hash256,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailabilityPendingExecutedEnvelope<E> {
    pub fn new(
        envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
        block_root: Hash256,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            envelope,
            block_root,
            payload_verification_outcome,
        }
    }
}

/// A payload envelope that has completed all payload processing checks including verification
/// by an EL client **and** has all requisite blob data to be imported into fork choice.
pub struct AvailableExecutedEnvelope<E: EthSpec> {
    pub envelope: AvailableEnvelope<E>,
    pub block_root: Hash256,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailableExecutedEnvelope<E> {
    pub fn new(
        envelope: AvailableEnvelope<E>,
        block_root: Hash256,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            envelope,
            block_root,
            payload_verification_outcome,
        }
    }
}

#[derive(Debug, AsRefStr)]
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
    BeaconChainError(Box<BeaconChainError>),
    /// Some Beacon State error
    BeaconStateError(BeaconStateError),
    /// Some EnvelopeProcessingError
    EnvelopeProcessingError(EnvelopeProcessingError),
    /// Error verifying the execution payload
    ExecutionPayloadError(ExecutionPayloadError),
    /// Optimistic sync is not supported for Gloas payload envelopes.
    OptimisticSyncNotSupported { block_root: Hash256 },
    /// The envelope's beacon block was not present in fork choice at import time.
    ///
    /// Unlike [`EnvelopeError::BlockRootUnknown`] (raised during gossip verification, where the
    /// block may simply not have arrived yet), this is raised during import where the block is
    /// expected to already be present, so it indicates an internal inconsistency.
    BlockRootNotInForkChoice(Hash256),
    /// An internal error occurred while importing the envelope (e.g. updating fork choice).
    InternalError(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl EnvelopeError {
    pub fn penalize_peer(&self) -> bool {
        match self {
            EnvelopeError::BadSignature
            | EnvelopeError::BuilderIndexMismatch { .. }
            | EnvelopeError::SlotMismatch { .. }
            | EnvelopeError::BlockHashMismatch { .. }
            | EnvelopeError::UnknownValidator { .. }
            | EnvelopeError::IncorrectBlockProposer { .. }
            | EnvelopeError::EnvelopeProcessingError(_) => true,
            EnvelopeError::ExecutionPayloadError(e) => e.penalize_peer(),
            EnvelopeError::BlockRootUnknown { .. }
            | EnvelopeError::PriorToFinalization { .. }
            | EnvelopeError::BeaconChainError(_)
            | EnvelopeError::BeaconStateError(_)
            | EnvelopeError::OptimisticSyncNotSupported { .. }
            | EnvelopeError::BlockRootNotInForkChoice(_)
            | EnvelopeError::InternalError(_) => false,
        }
    }
}

impl From<BeaconChainError> for EnvelopeError {
    fn from(e: BeaconChainError) -> Self {
        EnvelopeError::BeaconChainError(Box::new(e))
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
        EnvelopeError::BeaconChainError(Box::new(BeaconChainError::DBError(e)))
    }
}

impl From<EnvelopeError> for BlockError {
    fn from(e: EnvelopeError) -> Self {
        BlockError::EnvelopeError(Box::new(e))
    }
}

impl From<PayloadVerificationError> for EnvelopeError {
    fn from(e: PayloadVerificationError) -> Self {
        match e {
            PayloadVerificationError::ExecutionPayloadError(e) => {
                EnvelopeError::ExecutionPayloadError(e)
            }
            PayloadVerificationError::BeaconChainError(e) => EnvelopeError::BeaconChainError(e),
        }
    }
}

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
