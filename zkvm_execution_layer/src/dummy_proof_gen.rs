use crate::proof_generation::{ProofGenerationError, ProofGenerationResult, ProofGenerator};
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::sleep;
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId, Hash256};

/// Dummy proof generator for testing
///
/// This generator simulates the proof generation process with a configurable delay
/// and creates dummy proofs.
pub struct DummyProofGenerator {
    subnet_id: ExecutionProofSubnetId,
    generation_delay: Duration,
}

impl DummyProofGenerator {
    /// Create a new dummy generator for the specified subnet
    pub fn new(subnet_id: ExecutionProofSubnetId) -> Self {
        Self {
            subnet_id,
            generation_delay: Duration::from_millis(50), // Simulate some work
        }
    }

    /// Create a new dummy generator with custom generation delay
    pub fn with_delay(subnet_id: ExecutionProofSubnetId, delay: Duration) -> Self {
        Self {
            subnet_id,
            generation_delay: delay,
        }
    }
}

#[async_trait]
impl ProofGenerator for DummyProofGenerator {
    async fn generate(
        &self,
        payload_hash: &ExecutionBlockHash,
        block_root: &Hash256,
    ) -> ProofGenerationResult<ExecutionProof> {
        // Simulate proof generation work
        if !self.generation_delay.is_zero() {
            sleep(self.generation_delay).await;
        }

        // Create a dummy proof with some deterministic data
        let proof_data = vec![
            0xFF, // Magic byte for dummy proof
            self.subnet_id.as_u8(),
            // Include some payload hash bytes
            payload_hash.0[0],
            payload_hash.0[1],
            payload_hash.0[2],
            payload_hash.0[3],
        ];

        ExecutionProof::new(self.subnet_id, *payload_hash, *block_root, proof_data)
            .map_err(ProofGenerationError::ProofGenerationFailed)
    }

    fn subnet_id(&self) -> ExecutionProofSubnetId {
        self.subnet_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dummy_generator_success() {
        let subnet = ExecutionProofSubnetId::new(0).unwrap();
        let generator = DummyProofGenerator::new(subnet);
        let block_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        let result = generator.generate(&block_hash, &block_root).await;
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.subnet_id, subnet);
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.block_root, block_root);
        assert!(proof.proof_data_size() > 0);
    }

    #[tokio::test]
    async fn test_dummy_generator_deterministic() {
        let subnet = ExecutionProofSubnetId::new(1).unwrap();
        let generator = DummyProofGenerator::new(subnet);
        let block_hash = ExecutionBlockHash::repeat_byte(42);
        let block_root = Hash256::repeat_byte(99);

        // Generate twice
        let proof1 = generator.generate(&block_hash, &block_root).await.unwrap();
        let proof2 = generator.generate(&block_hash, &block_root).await.unwrap();

        // Should be identical
        assert_eq!(proof1.proof_data_slice(), proof2.proof_data_slice());
    }

    #[tokio::test]
    async fn test_dummy_generator_custom_delay() {
        // TODO(zkproofs): Maybe remove, mainly need it as a temp check
        let subnet = ExecutionProofSubnetId::new(0).unwrap();
        let delay = Duration::from_millis(1);
        let generator = DummyProofGenerator::with_delay(subnet, delay);
        let block_hash = ExecutionBlockHash::repeat_byte(1);
        let block_root = Hash256::repeat_byte(2);

        let start = tokio::time::Instant::now();
        let result = generator.generate(&block_hash, &block_root).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(elapsed >= delay);
    }
}
