use parking_lot::RwLock;

use crate::{ChainSpec, Epoch, EthSpec, ForkName, Hash256, Slot};
use std::collections::{ HashMap, HashSet};

/// Provides fork specific info like the current fork name and the fork digests corresponding to every valid fork.
#[derive(Debug)]
pub struct ForkContext {
    digest_epoch: RwLock<Epoch>,
    enabled_forks: HashSet<ForkName>,
    genesis_validators_root: Hash256,
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
        let enabled_forks = ForkName::list_all()
            .into_iter()
            .filter(|fork| spec.fork_epoch(*fork).is_some())
            .collect();

        let epoch_to_digest: HashMap<_, _> = spec
            .all_digest_epochs()
            .map(|epoch| {
                let fork_digest = spec.compute_fork_digest(genesis_validators_root, epoch);
                (epoch, fork_digest)
            })
            .collect();

        let digest_to_fork = epoch_to_digest
            .iter()
            .map(|(epoch, digest)| {
                let fork_name = spec.fork_name_at_epoch(*epoch);
                (*digest, fork_name)
            })
            .collect();

        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let digest_epoch = RwLock::new(
            epoch_to_digest
                .keys()
                .filter(|&&epoch| epoch <= current_epoch)
                .max()
                .cloned()
                .expect("should match atleast genesis epoch"),
        );

        Self {
            digest_epoch,
            enabled_forks,
            genesis_validators_root,
            digest_to_fork,
            spec: spec.clone(),
        }
    }

    /// Returns `true` if the provided `fork_name` exists in the `ForkContext` object.
    pub fn fork_exists(&self, fork_name: ForkName) -> bool {
        self.enabled_forks.contains(&fork_name)
    }

    /// Returns the `current_fork`.
    pub fn current_fork(&self) -> ForkName {
        self.spec.fork_name_at_epoch(self.digest_epoch())
    }

    /// Returns the current digest epoch
    pub fn digest_epoch(&self) -> Epoch {
        *self.digest_epoch.read()
    }

    pub fn next_fork_digest(&self) -> [u8; 4] {
        self.spec
            .next_digest_epoch(self.digest_epoch())
            .map(|epoch| {
                self.spec
                    .compute_fork_digest(self.genesis_validators_root, epoch)
            })
            .unwrap_or_default()
    }

    /// Updates the `digest_epoch` field to a new digest epoch.
    pub fn update_digest_epoch(&self, epoch: Epoch) {
        *self.digest_epoch.write() = epoch;
    }

    /// Returns the context bytes/fork_digest corresponding to the genesis fork version.
    pub fn genesis_context_bytes(&self) -> [u8; 4] {
        self.spec
            .compute_fork_digest(self.genesis_validators_root, Epoch::new(0))
    }

    /// Returns the fork type given the context bytes/fork_digest.
    /// Returns `None` if context bytes doesn't correspond to any valid `ForkName`.
    pub fn from_context_bytes(&self, context: [u8; 4]) -> Option<&ForkName> {
        self.digest_to_fork.get(&context)
    }

    // TODO: we *may* delete this entire object and just use the spec
    pub fn context_bytes(&self, epoch: Epoch) -> [u8; 4] {
        self.spec
            .compute_fork_digest(self.genesis_validators_root, epoch)
    }

    /// Returns all `fork_digest`s that are currently in the `ForkContext` object.
    pub fn all_fork_digests(&self) -> Vec<[u8; 4]> {
        self.digest_to_fork.keys().cloned().collect()
    }
}
