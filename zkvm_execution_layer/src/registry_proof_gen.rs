use crate::dummy_proof_gen::DummyProofGenerator;
use crate::proof_generation::DynProofGenerator;
use hashbrown::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use types::ExecutionProofSubnetId;

/// Registry mapping subnet IDs to proof generators
///
/// Each subnet can have a different zkVM/proof system, and this registry
/// maintains the mapping from subnet ID to the appropriate generator implementation.
/// Not all subnets need generators - nodes can verify without generating.
#[derive(Clone)]
pub struct GeneratorRegistry {
    generators: HashMap<ExecutionProofSubnetId, DynProofGenerator>,
}

impl GeneratorRegistry {
    /// Create a new empty generator registry
    pub fn new() -> Self {
        Self {
            generators: HashMap::new(),
        }
    }

    /// Create a registry with dummy generators for specified subnets
    /// This is useful for Phase 1 testing
    pub fn new_with_dummy_generators(enabled_subnets: HashSet<ExecutionProofSubnetId>) -> Self {
        let mut generators = HashMap::new();

        for subnet_id in enabled_subnets {
            generators.insert(
                subnet_id,
                Arc::new(DummyProofGenerator::new(subnet_id)) as DynProofGenerator,
            );
        }

        Self { generators }
    }

    pub fn register_generator(&mut self, generator: DynProofGenerator) {
        let subnet_id = generator.subnet_id();
        self.generators.insert(subnet_id, generator);
    }

    pub fn get_generator(&self, subnet_id: ExecutionProofSubnetId) -> Option<DynProofGenerator> {
        self.generators.get(&subnet_id).cloned()
    }

    /// Check if a generator is registered for a subnet
    pub fn has_generator(&self, subnet_id: ExecutionProofSubnetId) -> bool {
        self.generators.contains_key(&subnet_id)
    }

    /// Get the number of registered generators
    pub fn len(&self) -> usize {
        self.generators.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.generators.is_empty()
    }

    pub fn subnet_ids(&self) -> Vec<ExecutionProofSubnetId> {
        self.generators.keys().copied().collect()
    }
}

impl Default for GeneratorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_generators_registry() {
        let mut enabled_subnets = HashSet::new();
        enabled_subnets.insert(ExecutionProofSubnetId::new(0).unwrap());
        enabled_subnets.insert(ExecutionProofSubnetId::new(1).unwrap());

        let registry = GeneratorRegistry::new_with_dummy_generators(enabled_subnets);
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 2);

        assert!(registry.has_generator(ExecutionProofSubnetId::new(0).unwrap()));
        assert!(registry.has_generator(ExecutionProofSubnetId::new(1).unwrap()));
        assert!(!registry.has_generator(ExecutionProofSubnetId::new(2).unwrap()));
    }

    #[test]
    fn test_register_generator() {
        let mut registry = GeneratorRegistry::new();
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let generator = Arc::new(DummyProofGenerator::new(subnet_id));

        registry.register_generator(generator);

        assert_eq!(registry.len(), 1);
        assert!(registry.has_generator(subnet_id));
    }

    #[test]
    fn test_get_generator() {
        let mut enabled_subnets = HashSet::new();
        enabled_subnets.insert(ExecutionProofSubnetId::new(3).unwrap());

        let registry = GeneratorRegistry::new_with_dummy_generators(enabled_subnets);
        let subnet_id = ExecutionProofSubnetId::new(3).unwrap();

        let generator = registry.get_generator(subnet_id);
        assert!(generator.is_some());
        assert_eq!(generator.unwrap().subnet_id(), subnet_id);
    }

    #[test]
    fn test_subnet_ids() {
        let mut enabled_subnets = HashSet::new();
        enabled_subnets.insert(ExecutionProofSubnetId::new(0).unwrap());
        enabled_subnets.insert(ExecutionProofSubnetId::new(5).unwrap());

        let registry = GeneratorRegistry::new_with_dummy_generators(enabled_subnets.clone());
        let subnet_ids = registry.subnet_ids();

        assert_eq!(subnet_ids.len(), 2);
        for subnet_id in enabled_subnets {
            assert!(subnet_ids.contains(&subnet_id));
        }
    }
}
