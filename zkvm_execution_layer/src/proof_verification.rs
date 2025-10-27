use std::sync::Arc;
use thiserror::Error;
use types::{ExecutionProof, ExecutionProofId};

/// Result type for proof verification operations
pub type ProofVerificationResult<T> = Result<T, VerificationError>;

/// Errors that can occur during proof verification
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Unsupported proof ID: {0}")]
    UnsupportedProofID(ExecutionProofId),

    #[error("Proof size mismatch: expected {expected}, got {actual}")]
    ProofSizeMismatch { expected: usize, actual: usize },

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Trait for proof verification (one implementation per zkVM+EL combination)
pub trait ProofVerifier: Send + Sync {
    /// Verify that the proof is valid.
    ///
    /// TODO(zkproofs): we can probably collapse Ok(false) and Err or make Ok(false) an enum variant
    /// 
    /// Returns:
    /// - Ok(true) if valid,
    /// - Ok(false) if invalid (but well-formed)
    /// - Err if the proof is malformed or verification cannot be performed.
    fn verify(&self, proof: &ExecutionProof) -> ProofVerificationResult<bool>;

    fn proof_id(&self) -> ExecutionProofId;
}

/// Type-erased proof verifier
pub type DynProofVerifier = Arc<dyn ProofVerifier>;
