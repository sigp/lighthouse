//! Gossip verification for the EIP-8025 `execution_proof` topic.

use crate::observed_execution_proofs::{Error as ObservationError, ProofObservation};
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use proof_engine::{ProofEngineError, ProofVerificationOutcome};
use std::sync::Arc;
use tree_hash::TreeHash;
use types::execution::SignedExecutionProof;
use types::{Domain, Hash256, SignedRoot, Slot};

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
    /// The validator index does not exist (REJECT).
    UnknownValidatorIndex(u64),
    /// The validator is not active in the current epoch (REJECT).
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

/// A `SignedExecutionProof` verified for propagation on the gossip network.
pub struct VerifiedExecutionProof {
    pub proof: Arc<SignedExecutionProof>,
    pub block_slot: Slot,
}

pub async fn verify_execution_proof_for_gossip<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    proof: Arc<SignedExecutionProof>,
) -> Result<VerifiedExecutionProof, Error> {
    // [REJECT] `proof.proof_data` is non-empty. The `MAX_PROOF_SIZE` upper bound is enforced
    // structurally by the SSZ type at decode.
    if proof.message.proof_data.is_empty() {
        return Err(Error::EmptyProofData);
    }

    let proof_root = proof.message.tree_hash_root();
    let block_root = proof.beacon_block_root();
    let proof_type = proof.proof_type();
    let validator_index = proof.validator_index;

    // [IGNORE] The referenced beacon block is known. Its slot determines the fork for the
    // signing domain.
    let block_slot = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&block_root)
        .ok_or(Error::UnknownBlockRoot {
            beacon_block_root: block_root,
        })?
        .slot;

    // [IGNORE] Deduplication rules, checked before any expensive work.
    match chain
        .observed_execution_proofs
        .read()
        .check(
            proof_root,
            block_root,
            proof_type,
            validator_index,
            block_slot,
        )
        .map_err(Error::from)?
    {
        ProofObservation::ProofAlreadySeen => return Err(Error::ProofAlreadySeen),
        ProofObservation::ValidProofAlreadyKnown => return Err(Error::ValidProofAlreadyKnown),
        ProofObservation::DuplicateFromValidator => {
            return Err(Error::DuplicateFromValidator { validator_index });
        }
        ProofObservation::New => {}
    }

    // [REJECT] The validator is active in the current epoch.
    let head_snapshot = chain.head_snapshot();
    let current_epoch = chain.epoch()?;
    let validator = head_snapshot
        .beacon_state
        .validators()
        .get(validator_index as usize)
        .ok_or(Error::UnknownValidatorIndex(validator_index))?;
    if !validator.is_active_at(current_epoch) {
        return Err(Error::ValidatorNotActive { validator_index });
    }

    // [REJECT] The signature is valid with respect to the validator's public key.
    let fork_name = chain.spec.fork_name_at_slot::<T::EthSpec>(block_slot);
    let domain = chain.spec.compute_domain(
        Domain::ExecutionProof,
        chain.spec.fork_version_for_name(fork_name),
        chain.genesis_validators_root,
    );
    let signing_root = proof.message.signing_root(domain);
    {
        let pubkey_cache = chain.validator_pubkey_cache.read();
        let pubkey = pubkey_cache
            .get(validator_index as usize)
            .ok_or(Error::UnknownValidatorIndex(validator_index))?;
        if !proof.signature.verify(pubkey, signing_root) {
            return Err(Error::InvalidSignature);
        }
    }

    // Only record the validator's attempt after the signature binds `validator_index`;
    // recording earlier would let unauthenticated messages suppress honest provers.
    if !chain
        .observed_execution_proofs
        .write()
        .observe_signature_verified_proof(
            proof_root,
            block_root,
            proof_type,
            validator_index,
            block_slot,
        )
        .map_err(Error::from)?
    {
        // Lost a race against a concurrent copy of the same proof.
        return Err(Error::ProofAlreadySeen);
    }

    // [REJECT] The proof verifies via the proof engine.
    //
    // Proof verification is a fast crypto check against a localhost sidecar (and may be embedded
    // in-process in the future), so awaiting it here does not hold up the processor significantly.
    let proof_engine = chain
        .proof_engine
        .as_ref()
        .ok_or(Error::ProofEngineMissing)?;
    match proof_engine
        .verify_execution_proof(&proof.message)
        .await
        .map_err(Error::ProofEngine)?
    {
        ProofVerificationOutcome::Invalid => return Err(Error::InvalidProof),
        ProofVerificationOutcome::Valid => {}
    }

    chain
        .observed_execution_proofs
        .write()
        .observe_valid_proof(block_root, proof_type);
    Ok(VerifiedExecutionProof { proof, block_slot })
}
