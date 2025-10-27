use crate::dummy_proof_verifier::DummyVerifier;
use crate::proof_verification::DynProofVerifier;
use hashbrown::HashMap;
use std::sync::Arc;
use types::ExecutionProofId;

/// Registry mapping subnet IDs to proof verifiers
///
/// Each subnet can have a different zkVM/proof system, and this registry
/// maintains the mapping from subnet ID to the appropriate verifier implementation.
#[derive(Clone)]
pub struct VerifierRegistry {
    verifiers: HashMap<ExecutionProofId, DynProofVerifier>,
}

impl VerifierRegistry {
    /// Create a new empty verifier registry
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Create a registry with dummy verifiers for all subnets
    /// This is useful for Phase 1 testing
    pub fn new_with_dummy_verifiers() -> Self {
        let mut verifiers = HashMap::new();

        // Register dummy verifiers for all 8 subnets
        for id in 0..types::EXECUTION_PROOF_TYPE_COUNT {
            if let Ok(proof_id) = ExecutionProofId::new(id) {
                verifiers.insert(
                    proof_id,
                    Arc::new(DummyVerifier::new(proof_id)) as DynProofVerifier,
                );
            }
        }

        Self { verifiers }
    }

    /// Register a verifier for a specific subnet
    pub fn register_verifier(&mut self, verifier: DynProofVerifier) {
        let subnet_id = verifier.proof_id();
        self.verifiers.insert(subnet_id, verifier);
    }

    /// Get a verifier for a specific proof ID
    pub fn get_verifier(&self, proof_id: ExecutionProofId) -> Option<DynProofVerifier> {
        self.verifiers.get(&proof_id).cloned()
    }

    /// Check if a verifier is registered for a proof ID
    pub fn has_verifier(&self, proof_id: ExecutionProofId) -> bool {
        self.verifiers.contains_key(&proof_id)
    }

    /// Get the number of registered verifiers
    pub fn len(&self) -> usize {
        self.verifiers.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.verifiers.is_empty()
    }

    /// Get all registered subnet IDs
    pub fn proof_ids(&self) -> Vec<ExecutionProofId> {
        self.verifiers.keys().copied().collect()
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = VerifierRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_dummy_verifiers_registry() {
        let registry = VerifierRegistry::new_with_dummy_verifiers();
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 8); // All 8 subnets

        // Check all proof IDs are registered
        for id in 0..8 {
            let proof_id = ExecutionProofId::new(id).unwrap();
            assert!(registry.has_verifier(proof_id));
            assert!(registry.get_verifier(proof_id).is_some());
        }
    }

    #[test]
    fn test_register_verifier() {
        let mut registry = VerifierRegistry::new();
        let proof_id = ExecutionProofId::new(0).unwrap();
        let verifier = Arc::new(DummyVerifier::new(proof_id));

        registry.register_verifier(verifier);

        assert_eq!(registry.len(), 1);
        assert!(registry.has_verifier(proof_id));
    }

    #[test]
    fn test_get_verifier() {
        let registry = VerifierRegistry::new_with_dummy_verifiers();
        let proof_id = ExecutionProofId::new(3).unwrap();

        let verifier = registry.get_verifier(proof_id);
        assert!(verifier.is_some());
        assert_eq!(verifier.unwrap().proof_id(), proof_id);
    }

    #[test]
    fn test_proof_ids() {
        let registry = VerifierRegistry::new_with_dummy_verifiers();
        let proof_ids = registry.proof_ids();

        assert_eq!(proof_ids.len(), 8);
        for id in 0..8 {
            let proof_id = ExecutionProofId::new(id).unwrap();
            assert!(proof_ids.contains(&proof_id));
        }
    }
}
