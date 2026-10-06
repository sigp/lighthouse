//! Gossip verification for the EIP-8025 `execution_proof` topic.

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockError};
use proof_engine::ProofEngineError;
use std::sync::Arc;
use tracing::debug;
use types::{ExecutionBlockHash, Hash256, Slot};

pub mod gossip_verified_execution_proof;
pub mod observed_execution_proofs;

pub use gossip_verified_execution_proof::{
    GossipVerificationContext, GossipVerifiedExecutionProof,
};
pub use observed_execution_proofs::ObservedExecutionProofs;

use observed_execution_proofs::Error as ObservationError;

/// Distinct proof systems that must prove a payload before fork choice calls it valid. More than
/// one means a soundness bug in a single prover isn't enough to fool us.
///
/// Which systems count is the engine's call, we only see its `VALID`. The count is ours because
/// we're the only ones who see the whole set.
///
/// TODO(9658): make configurable. https://github.com/sigp/lighthouse/issues/9658
pub const REQUIRED_EXECUTION_PROOFS: usize = 2;

#[derive(Debug)]
pub enum Error {
    /// The proof has already been seen (IGNORE).
    ProofAlreadySeen,
    /// A valid proof for this `(block_root, proof_type)` is already known (IGNORE).
    ValidProofAlreadyKnown,
    /// This validator already submitted a proof for this `(block_root, proof_type)` (IGNORE).
    DuplicateFromValidator {
        validator_index: u64,
    },
    /// The referenced beacon block is not known to fork choice (IGNORE).
    UnknownBlockRoot {
        beacon_block_root: Hash256,
    },
    /// The referenced beacon block is already finalized (IGNORE).
    PastFinalizedSlot {
        slot: Slot,
        finalized_slot: Slot,
    },
    /// `proof_data` is empty (REJECT).
    EmptyProofData,
    /// The proof's public input is not the payload the block committed to (REJECT).
    PayloadMismatch {
        proof_block_hash: ExecutionBlockHash,
    },
    /// The validator index does not exist (REJECT).
    UnknownValidatorIndex(u64),
    /// The validator is not active at the referenced block's epoch (REJECT).
    ValidatorNotActive {
        validator_index: u64,
    },
    /// The signature is invalid (REJECT).
    InvalidSignature,
    /// The proof engine rejected the proof (REJECT).
    InvalidProof,
    /// No proof engine is configured; the node should not be subscribed to the topic.
    ProofEngineMissing,
    /// The proof engine could not be reached or answered malformed (IGNORE).
    ProofEngine(ProofEngineError),
    BeaconChainError(Box<BeaconChainError>),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<ObservationError> for Error {
    fn from(e: ObservationError) -> Self {
        match e {
            ObservationError::FinalizedProof {
                slot,
                finalized_slot,
            } => Error::PastFinalizedSlot {
                slot,
                finalized_slot,
            },
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Whether EIP-8025 proofs decide payload validity here, which takes a proof engine.
    pub(crate) fn execution_proofs_enabled(&self) -> bool {
        self.proof_engine.is_some()
    }

    /// Whether `block_root`'s payload has proofs from as many proof systems as we require.
    pub(crate) fn execution_proofs_satisfied(&self, block_root: &Hash256) -> bool {
        self.observed_execution_proofs
            .read()
            .valid_proof_count(block_root)
            >= REQUIRED_EXECUTION_PROOFS
    }

    /// Tell fork choice `block_root`'s payload is valid, once its proofs are all in.
    ///
    /// Gossip verification has already counted the proof, so this only reads the count. The read
    /// happens under the fork choice write lock, which `import.rs` relies on: were it read outside,
    /// a proof completing concurrently with the import could be missed by both paths.
    pub async fn promote_payload_if_proven(
        self: &Arc<Self>,
        block_root: Hash256,
    ) -> Result<(), BlockError> {
        if !self.execution_proofs_satisfied(&block_root) {
            return Ok(());
        }

        // The bid commits the payload's execution block hash, which is how fork choice names it.
        let payload_block_hash = self
            .get_or_load_gloas_payload_bid(block_root)
            .await?
            .message
            .block_hash;

        debug!(?block_root, "Execution proofs complete, validating payload");
        let chain = self.clone();
        self.spawn_blocking_handle(
            move || {
                chain
                    .canonical_head
                    .fork_choice_write_lock()
                    .on_valid_execution_payload(payload_block_hash)
                    .map_err(|e| BlockError::BeaconChainError(Box::new(e.into())))
            },
            "validate_proven_payload",
        )
        .await?
    }
}
