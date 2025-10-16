use std::sync::Arc;
use thiserror::Error;
use types::{ExecutionProof, ExecutionProofSubnetId};

/// Result type for proof verification operations
pub type ProofVerificationResult<T> = Result<T, VerificationError>;

/// Errors that can occur during proof verification
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Unsupported subnet: {0}")]
    UnsupportedSubnet(ExecutionProofSubnetId),

    #[error("Proof size mismatch: expected {expected}, got {actual}")]
    ProofSizeMismatch { expected: usize, actual: usize },

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Trait for proof verification (one implementation per zkVM+EL combination)
pub trait ProofVerifier: Send + Sync {
    /// Verify that the proof is valid for the given execution payload
    ///
    /// Returns :
    /// - Ok(true) if valid,
    /// - Ok(false) if invalid (but well-formed)
    /// - Err if the proof is malformed or verification cannot be performed.
    /// TODO(zkproofs): Maybe make Ok(false) an enum variant
    fn verify(
        &self,
        payload_hash: &types::ExecutionBlockHash,
        proof: &ExecutionProof,
    ) -> ProofVerificationResult<bool>;

    fn subnet_id(&self) -> ExecutionProofSubnetId;
}

/// Type-erased proof verifier
pub type DynProofVerifier = Arc<dyn ProofVerifier>;
