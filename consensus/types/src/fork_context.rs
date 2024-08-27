use parking_lot::RwLock;

use crate::{ChainSpec, EthSpec, ForkName, Hash256, Slot};
use std::collections::HashMap;

/// Provides fork specific info like the current fork name and the fork digests corresponding to every valid fork.
#[derive(Debug)]
pub struct ForkContext {
    current_fork: RwLock<ForkName>,
    fork_to_digest: HashMap<ForkName, [u8; 4]>,
    digest_to_fork: HashMap<[u8; 4], ForkName>,
    pub spec: ChainSpec,
}

impl ForkContext {
    /// Creates a new `ForkContext` object by enumerating all enabled forks and computing their
    /// fork digest.
    ///
    /// A fork is disabled in the `ChainSpec` if the activation slot corresponding to that fork is `None`.
    pub fn new<E: EthSpec>(
        current_slot: Slot,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let mut fork_to_digest = vec![(
            ForkName::Base,
            ChainSpec::compute_fork_digest(spec.genesis_fork_version, genesis_validators_root),
        )];

        // Only add Altair to list of forks if it's enabled
        // Note: `altair_fork_epoch == None` implies altair hasn't been activated yet on the config.
        if spec.altair_fork_epoch.is_some() {
            fork_to_digest.push((
                ForkName::Altair,
                ChainSpec::compute_fork_digest(spec.altair_fork_version, genesis_validators_root),
            ));
        }

        // Only add Bellatrix to list of forks if it's enabled
        // Note: `bellatrix_fork_epoch == None` implies bellatrix hasn't been activated yet on the config.
        if spec.bellatrix_fork_epoch.is_some() {
            fork_to_digest.push((
                ForkName::Bellatrix,
                ChainSpec::compute_fork_digest(
                    spec.bellatrix_fork_version,
                    genesis_validators_root,
                ),
            ));
        }

        if spec.capella_fork_epoch.is_some() {
            fork_to_digest.push((
                ForkName::Capella,
                ChainSpec::compute_fork_digest(spec.capella_fork_version, genesis_validators_root),
            ));
        }

        if spec.deneb_fork_epoch.is_some() {
            fork_to_digest.push((
                ForkName::Deneb,
                ChainSpec::compute_fork_digest(spec.deneb_fork_version, genesis_validators_root),
            ));
        }

        if spec.electra_fork_epoch.is_some() {
            fork_to_digest.push((
                ForkName::Electra,
                ChainSpec::compute_fork_digest(spec.electra_fork_version, genesis_validators_root),
            ));
        }

        if spec.eip7732_fork_epoch.is_some() {
            fork_to_digest.push((
                ForkName::EIP7732,
                ChainSpec::compute_fork_digest(spec.eip7732_fork_version, genesis_validators_root),
            ));
        }

        let fork_to_digest: HashMap<ForkName, [u8; 4]> = fork_to_digest.into_iter().collect();

        let digest_to_fork = fork_to_digest
            .clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect();

        Self {
            current_fork: RwLock::new(spec.fork_name_at_slot::<E>(current_slot)),
            fork_to_digest,
            digest_to_fork,
            spec: spec.clone(),
        }
    }

    /// Returns `true` if the provided `fork_name` exists in the `ForkContext` object.
    pub fn fork_exists(&self, fork_name: ForkName) -> bool {
        self.fork_to_digest.contains_key(&fork_name)
    }

    /// Returns the `current_fork`.
    pub fn current_fork(&self) -> ForkName {
        *self.current_fork.read()
    }

    /// Updates the `current_fork` field to a new fork.
    pub fn update_current_fork(&self, new_fork: ForkName) {
        *self.current_fork.write() = new_fork;
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

    /// Returns all `fork_digest`s that are currently in the `ForkContext` object.
    pub fn all_fork_digests(&self) -> Vec<[u8; 4]> {
        self.digest_to_fork.keys().cloned().collect()
    }
}
