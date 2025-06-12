use parking_lot::RwLock;

use crate::{ChainSpec, EthSpec, ForkName, Hash256, Slot};
use std::{collections::HashMap, marker::PhantomData};

/// Provides fork specific info like the current fork name and the fork digests corresponding to every valid fork.
#[derive(Debug)]
pub struct ForkContext<E: EthSpec> {
    relevant_epoch: Epoch,
    enabled_forks: HashSet<ForkName>,
    genesis_validators_root: Hash256,
    epoch_to_digest: BTreeMap<Epoch, [u8; 4]>,
    digest_to_fork: HashMap<[u8; 4], ForkName>,
    pub spec: ChainSpec,
    phantom_data: PhantomData<E>,
}

impl<E: EthSpec> ForkContext<E> {
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
            .filter(|fork| spec.fork_epoch(fork).is_some());

        let epoch_to_digest = spec
            .all_digest_epochs()
            .into_iter()
            .map(|epoch| {
                let fork_version = spec.fork_version_for_epoch(epoch);
                let fork_digest = spec.compute_fork_digest(genesis_validators_root, epoch);
                (epoch, fork_digest)
            })
            .collect();

        let digest_to_fork = epoch_to_digest
            .iter()
            .map(|(epoch, digest)| {
                let fork_name = spec.fork_name_at_epoch(epoch);
                (*digest, fork_name)
            })
            .collect();

        let relevant_epoch = RwLock::new(current_slot.epoch(E::slots_per_epoch()));

        Self {
            relevant_epoch,
            enabled_forks,
            genesis_validators_root,
            epoch_to_digest,
            digest_to_fork,
            spec: spec.clone(),
            phantom_data: PhantomData::<E>::default(),
        }
    }

    /// Returns `true` if the provided `fork_name` exists in the `ForkContext` object.
    pub fn fork_exists(&self, fork_name: ForkName) -> bool {
        self.enabled_forks.contains_key(&fork_name)
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

    // TODO: we may delete this entire object and just use the spec
    pub fn context_bytes(&self, slot: Slot) -> [u8; 4] {
        let epoch = slot.epoch(E::slots_per_epoch());
        self.spec
            .compute_fork_digest(self.genesis_validators_root, epoch)
    }

    /// Returns all `fork_digest`s that are currently in the `ForkContext` object.
    pub fn all_fork_digests(&self) -> Vec<[u8; 4]> {
        self.digest_to_fork.keys().cloned().collect()
    }
}
