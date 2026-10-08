//! Gossip verification for the EIP-8025 `execution_proof` topic.

use crate::metrics;
use crate::validator_monitor::get_slot_delay_ms;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockError};
use proof_engine::ProofEngineError;
use slot_clock::timestamp_now;
use std::sync::Arc;
use strum::IntoStaticStr;
use tracing::debug;
use types::{Hash256, Slot};

pub mod gossip_verified_execution_proof;
pub mod observed_execution_proofs;

pub use gossip_verified_execution_proof::{
    GossipVerificationContext, GossipVerifiedExecutionProof,
};
pub use observed_execution_proofs::ObservedExecutionProofs;

use observed_execution_proofs::Error as ObservationError;

/// Distinct proof systems that must prove a payload before fork choice calls it valid.
///
/// TODO(9658): make configurable. https://github.com/sigp/lighthouse/issues/9658
pub const REQUIRED_EXECUTION_PROOFS: usize = 2;

/// How a proof reached us, which decides whether deduplication rejects it.
#[derive(Clone, Copy)]
pub enum ProofSource {
    Gossip,
    Http,
}

#[derive(Debug, IntoStaticStr)]
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
    /// The payload this proof is about has not been seen (IGNORE).
    PayloadUnavailable {
        beacon_block_root: Hash256,
    },
    /// `proof_data` is empty (REJECT).
    EmptyProofData,
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
    /// Whether EIP-8025 proofs decide payload validity here.
    pub fn execution_proofs_enabled(&self) -> bool {
        self.proof_engine.is_some()
    }

    /// Tell fork choice `block_root`'s payload is valid.
    pub async fn promote_payload_if_proven(
        self: &Arc<Self>,
        block_root: Hash256,
        block_slot: Slot,
    ) -> Result<(), BlockError> {
        // Exactly at the threshold: a later proof type would re-promote a valid payload.
        if self
            .observed_execution_proofs
            .read()
            .valid_proof_count(&block_root)
            != REQUIRED_EXECUTION_PROOFS
        {
            return Ok(());
        }

        debug!(?block_root, "Execution proofs complete, validating payload");
        let chain = self.clone();
        self.spawn_blocking_handle(
            move || {
                chain
                    .canonical_head
                    .fork_choice_write_lock()
                    .on_valid_execution_payload_by_block_root(block_root)
                    .map_err(|e| BlockError::BeaconChainError(Box::new(e.into())))
            },
            "validate_proven_payload",
        )
        .await??;
        metrics::inc_counter(&metrics::EXECUTION_PROOF_PROMOTIONS);
        metrics::observe(
            &metrics::EXECUTION_PROOF_PROMOTION_LAG,
            get_slot_delay_ms(timestamp_now(), block_slot, &self.slot_clock).as_secs_f64(),
        );
        Ok(())
    }
}
