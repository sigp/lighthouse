use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use types::{execution_proof::DEFAULT_MIN_PROOFS_REQUIRED, ExecutionProofId};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKVMExecutionLayerConfig {
    /// Minimum number of proofs required from _different_ proof types (proof_ids)
    /// in order for the node to mark an execution payload as VALID.
    ///
    /// Note: All nodes receive ALL proof types via the single execution_proof gossip topic.
    pub min_proofs_required: usize,

    /// Which proof types to generate (empty if not generating proofs)
    /// The proof ID identifies the zkVM+EL combination (e.g., 0=SP1+Reth, 1=Risc0+Geth)
    pub generation_proof_types: HashSet<ExecutionProofId>,

    /// Proof cache size (number of execution block hashes to cache proofs for)
    /// TODO(zkproofs): remove since we use da_checker for proof caches
    pub proof_cache_size: usize,
}

impl Default for ZKVMExecutionLayerConfig {
    fn default() -> Self {
        Self {
            min_proofs_required: DEFAULT_MIN_PROOFS_REQUIRED,
            generation_proof_types: HashSet::new(),
            // TODO(zkproofs): This is somewhat arbitrary. The number was computed
            // by NUMBER_OF_BLOCKS_BEFORE_FINALIZATION * NUM_PROOFS_PER_BLOCK = 64 * 8
            // We can change it to be more rigorous/scientific
            proof_cache_size: 64 * 8,
        }
    }
}

impl ZKVMExecutionLayerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_proofs_required == 0 {
            return Err("min_proofs_required must be at least 1".to_string());
        }

        if self.proof_cache_size == 0 {
            return Err("proof_cache_size must be at least 1".to_string());
        }

        // Note: We do NOT validate that generation_proof_types.len() >= min_proofs_required
        // because proof-generating nodes validate via their execution layer, not via proofs.
        // Only lightweight verifier nodes (without EL) need to wait for min_proofs_required.

        Ok(())
    }

    /// Create a builder for the config
    /// TODO(zkproofs): I think we can remove this
    pub fn builder() -> ZKVMExecutionLayerConfigBuilder {
        ZKVMExecutionLayerConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct ZKVMExecutionLayerConfigBuilder {
    min_proofs_required: Option<usize>,
    generation_proof_types: HashSet<ExecutionProofId>,
    proof_cache_size: Option<usize>,
}

impl ZKVMExecutionLayerConfigBuilder {
    pub fn min_proofs_required(mut self, min: usize) -> Self {
        self.min_proofs_required = Some(min);
        self
    }

    pub fn generation_proof_types(mut self, proof_types: HashSet<ExecutionProofId>) -> Self {
        self.generation_proof_types = proof_types;
        self
    }

    pub fn add_generation_proof_type(mut self, proof_type: ExecutionProofId) -> Self {
        self.generation_proof_types.insert(proof_type);
        self
    }

    pub fn proof_cache_size(mut self, size: usize) -> Self {
        self.proof_cache_size = Some(size);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<ZKVMExecutionLayerConfig, String> {
        let config = ZKVMExecutionLayerConfig {
            min_proofs_required: self.min_proofs_required.unwrap_or(DEFAULT_MIN_PROOFS_REQUIRED),
            generation_proof_types: self.generation_proof_types,
            proof_cache_size: self.proof_cache_size.unwrap_or(1024),
        };

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let proof_type_0 = ExecutionProofId::new(0).unwrap();
        let proof_type_1 = ExecutionProofId::new(1).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_generation_proof_type(proof_type_0)
            .add_generation_proof_type(proof_type_1)
            .min_proofs_required(2)
            .build();

        assert!(config.is_ok());
    }

    #[test]
    fn test_valid_config_with_generation() {
        let proof_type_0 = ExecutionProofId::new(0).unwrap();
        let proof_type_1 = ExecutionProofId::new(1).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_generation_proof_type(proof_type_0)
            .add_generation_proof_type(proof_type_1)
            .min_proofs_required(1)
            .proof_cache_size(512)
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.generation_proof_types.len(), 2);
        assert_eq!(config.min_proofs_required, 1);
        assert_eq!(config.proof_cache_size, 512);
    }

    #[test]
    fn test_min_proofs_required_zero() {
        let config = ZKVMExecutionLayerConfig::builder()
            .min_proofs_required(0) // Invalid: must be > 0
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_no_generation_proof_types() {
        // Node can receive and verify proofs without generating any
        let config = ZKVMExecutionLayerConfig::builder()
            .min_proofs_required(2)
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(config.generation_proof_types.is_empty());
    }

    #[test]
    fn test_generation_proof_types_less_than_min() {
        // Proof-generating nodes validate via EL, not proofs
        // They can generate any number of proof types regardless of min_proofs_required
        let proof_type_0 = ExecutionProofId::new(0).unwrap();

        let config = ZKVMExecutionLayerConfig::builder()
            .add_generation_proof_type(proof_type_0)
            .min_proofs_required(2) 
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.generation_proof_types.len(), 1);
        assert_eq!(config.min_proofs_required, 2);
    }
}
