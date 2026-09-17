//! In-process EIP-8025 proof verification.

mod config;
#[cfg(feature = "ere-verifier")]
pub mod ere;
#[cfg(feature = "test-utils")]
pub mod test_utils;

use std::sync::Arc;
use types::execution::{ExecutionProof, ProofType};

pub use config::{ExecutionProofConfig, ProofEngineConfig};

/// Errors raised while initializing or running a proof verifier.
#[derive(Debug)]
pub enum ProofEngineError {
    /// The configured proof verifier could not initialize or complete verification.
    ProofVerifierError(String),
    /// No verifier is configured for the proof's EIP-8025 proof type.
    UnconfiguredProofType(ProofType),
}

/// Outcome of proof verification. `Invalid` means the artifact does not verify; it says nothing
/// about the validity of the payload it claims to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationOutcome {
    /// The proof verifies against its reconstructed public input.
    Valid,
    /// The proof or its public values are invalid.
    Invalid,
}

/// Interface used by the beacon chain to verify reconstructed execution proofs.
pub trait ProofEngineT: Send + Sync + 'static {
    /// Verify a reconstructed execution proof.
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError>;
}

/// Cloneable handle to an execution-proof verifier.
#[derive(Clone)]
pub struct ProofEngine {
    inner: Arc<dyn ProofEngineT>,
}

impl std::fmt::Debug for ProofEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofEngine").finish_non_exhaustive()
    }
}

impl ProofEngine {
    /// Wrap an execution-proof verifier in a shared handle.
    pub fn new(engine: impl ProofEngineT) -> Self {
        Self {
            inner: Arc::new(engine),
        }
    }

    /// Verify a reconstructed execution proof with the wrapped implementation.
    pub fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        self.inner.verify_execution_proof(proof)
    }
}
