use crate::{ChainSpec, ForkName, Hash256};
use std::collections::HashMap;

/// Provides fork specific info like the fork digest corresponding to a fork.
#[derive(Debug, Clone)]
pub struct ForkContext {
    fork_to_digest: HashMap<ForkName, [u8; 4]>,
    digest_to_fork: HashMap<[u8; 4], ForkName>,
}

impl ForkContext {
    /// Creates a new `ForkContext` object by enumerating all enabled forks and computing their
    /// fork digest.
    ///
    /// A fork is disabled in the `ChainSpec` if the activation slot corresponding to that fork is `None`.
    pub fn new(genesis_validators_root: Hash256, spec: &ChainSpec) -> Self {
        let mut fork_to_digest = vec![(
            ForkName::Base,
            ChainSpec::compute_fork_digest(spec.genesis_fork_version, genesis_validators_root),
        )];

        // Only add Altair to list of forks if it's enabled (i.e. spec.altair_fork_slot != None)
        if spec.altair_fork_slot.is_some() {
            fork_to_digest.push((
                ForkName::Altair,
                ChainSpec::compute_fork_digest(spec.altair_fork_version, genesis_validators_root),
            ))
        }

        let fork_to_digest: HashMap<ForkName, [u8; 4]> = fork_to_digest.into_iter().collect();

        let digest_to_fork = fork_to_digest
            .clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect();

        Self {
            fork_to_digest,
            digest_to_fork,
        }
    }

    /// Returns the context bytes/fork_digest corresponding to the genesis fork version.
    pub fn genesis_context_bytes(&self) -> [u8; 4] {
        *self
            .fork_to_digest
            .get(&ForkName::Base)
            .expect("ForkContext must contain genesis context bytes")
    }

    /// Returns the fork type given the context bytes/fork_digest.
    /// Returns `None` if context bytes doesn't correspond to any valid `ForkName`.
    pub fn from_context_bytes(&self, context: [u8; 4]) -> Option<&ForkName> {
        self.digest_to_fork.get(&context)
    }

    /// Returns the context bytes/fork_digest corresponding to a fork name.
    /// Returns `None` if the `ForkName` has not been initialized.
    pub fn to_context_bytes(&self, fork_name: ForkName) -> Option<[u8; 4]> {
        self.fork_to_digest.get(&fork_name).cloned()
    }
}
