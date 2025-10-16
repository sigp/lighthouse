use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use types::{ExecutionProof, ExecutionProofSubnetId};

/// Result type for proof generation operations
pub type ProofGenerationResult<T> = Result<T, ProofGenerationError>;

/// Errors that can occur during proof generation
#[derive(Debug, Error)]
pub enum ProofGenerationError {
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Missing execution witness data: {0}")]
    MissingWitnessData(String),

    #[error("Invalid execution witness: {0}")]
    InvalidWitness(String),

    #[error("Proof generation timeout")]
    Timeout,

    #[error("Insufficient resources: {0}")]
    InsufficientResources(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Trait for proof generation (one implementation per zkVM)
///
/// Each proof system (RISC Zero, SP1, etc.) implements this trait
/// to generate proofs for execution payloads from their subnet.
#[async_trait]
pub trait ProofGenerator: Send + Sync {
    /// Generate a proof for the given execution payload
    ///
    /// Note: This is a computationally expensive operation and should be run
    /// in a background task.
    async fn generate(
        &self,
        payload_hash: &types::ExecutionBlockHash,
        block_root: &types::Hash256,
    ) -> ProofGenerationResult<ExecutionProof>;

    /// Get the subnet ID this generator produces proofs for
    fn subnet_id(&self) -> ExecutionProofSubnetId;
}

/// Type-erased proof generator mainly for convenience
/// TODO(zkproofs): Check if we can remove this
pub type DynProofGenerator = Arc<dyn ProofGenerator>;
