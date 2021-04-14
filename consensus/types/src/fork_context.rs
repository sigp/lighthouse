use crate::{ChainSpec, ForkType, Hash256, Slot};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ForkContext {
    current_fork: ForkType,
    fork_to_digest: HashMap<ForkType, [u8; 4]>,
    digest_to_fork: HashMap<[u8; 4], ForkType>,
}

impl ForkContext {
    pub fn new(current_slot: Slot, genesis_validators_root: Hash256, spec: &ChainSpec) -> Self {
        let genesis_fork_version = spec.genesis_fork_digest(genesis_validators_root);
        let altair_fork_version = spec.altair_fork_digest(genesis_validators_root);
        let fork_to_digest = vec![
            (ForkType::Genesis, genesis_fork_version),
            (ForkType::Altair, altair_fork_version),
        ]
        .into_iter()
        .collect();
        let digest_to_fork = vec![
            (genesis_fork_version, ForkType::Genesis),
            (altair_fork_version, ForkType::Altair),
        ]
        .into_iter()
        .collect();

        Self {
            fork_to_digest,
            digest_to_fork,
            current_fork: ForkType::from_slot(current_slot, spec),
        }
    }

    /// Updates the `current_fork` field.
    pub fn update_current_fork(&mut self, fork_type: ForkType) {
        self.current_fork = fork_type;
    }

    /// Returns the fork type given the context bytes/fork_digest.
    /// Returns None if context bytes doesn't correspond to any valid ForkType.
    pub fn from_context_bytes(&self, context: [u8; 4]) -> Option<&ForkType> {
        self.digest_to_fork.get(&context)
    }

    /// Returns the context bytes/fork_digest corresponding to a fork type
    pub fn to_context_bytes(&self, fork_type: ForkType) -> [u8; 4] {
        self.fork_to_digest
            .get(&fork_type)
            .expect("All possible forks are initialized")
            .clone()
    }
}
