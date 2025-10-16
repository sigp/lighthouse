use parking_lot::RwLock;

use crate::{ChainSpec, Epoch, EthSpec, ForkName, Hash256, Slot};
use std::collections::BTreeMap;

/// Represents a hard fork in the consensus protocol.
///
/// A hard fork can be one of two types:
/// * A named fork (represented by `ForkName`) which introduces protocol changes.
/// * A blob-parameter-only (BPO) fork which only modifies blob parameters.
///
/// For BPO forks, the `fork_name` remains unchanged from the previous fork,
/// but the `fork_epoch` and `fork_digest` will be different to reflect the
/// new blob parameter changes.
#[derive(Debug, Clone)]
pub struct HardFork {
    fork_name: ForkName,
    fork_epoch: Epoch,
    fork_digest: [u8; 4],
}

impl HardFork {
    pub fn new(fork_name: ForkName, fork_digest: [u8; 4], fork_epoch: Epoch) -> HardFork {
        HardFork {
            fork_name,
            fork_epoch,
            fork_digest,
        }
    }
}

/// Provides fork specific info like the current fork name and the fork digests corresponding to every valid fork.
#[derive(Debug)]
pub struct ForkContext {
    current_fork: RwLock<HardFork>,
    epoch_to_forks: BTreeMap<Epoch, HardFork>,
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
        let epoch_to_forks: BTreeMap<_, _> = spec
            .all_digest_epochs()
            .map(|epoch| {
                let fork_name = spec.fork_name_at_epoch(epoch);
                let fork_digest = spec.compute_fork_digest(genesis_validators_root, epoch);
                (epoch, HardFork::new(fork_name, fork_digest, epoch))
            })
            .collect();

        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let current_fork = epoch_to_forks
            .values()
            .filter(|&fork| fork.fork_epoch <= current_epoch)
            .next_back()
            .cloned()
            .expect("should match at least genesis epoch");

        Self {
            current_fork: RwLock::new(current_fork),
            epoch_to_forks,
            spec: spec.clone(),
        }
    }

    /// Returns `true` if the provided `fork_name` exists in the `ForkContext` object.
    pub fn fork_exists(&self, fork_name: ForkName) -> bool {
        self.spec.fork_epoch(fork_name).is_some()
    }

    /// Returns the current fork name.
    pub fn current_fork_name(&self) -> ForkName {
        self.current_fork.read().fork_name
    }

    /// Returns the current fork epoch.
    pub fn current_fork_epoch(&self) -> Epoch {
        self.current_fork.read().fork_epoch
    }

    /// Returns the current fork digest.
    pub fn current_fork_digest(&self) -> [u8; 4] {
        self.current_fork.read().fork_digest
    }

    /// Returns the next fork digest. If there's no future fork, returns the current fork digest.
    pub fn next_fork_digest(&self) -> Option<[u8; 4]> {
        let current_fork_epoch = self.current_fork_epoch();
        self.epoch_to_forks
            .range(current_fork_epoch..)
            .nth(1)
            .map(|(_, fork)| fork.fork_digest)
    }

    /// Updates the `digest_epoch` field to a new digest epoch.
    pub fn update_current_fork(
        &self,
        new_fork_name: ForkName,
        new_fork_digest: [u8; 4],
        new_fork_epoch: Epoch,
    ) {
        debug_assert!(self.epoch_to_forks.contains_key(&new_fork_epoch));
        *self.current_fork.write() = HardFork::new(new_fork_name, new_fork_digest, new_fork_epoch);
    }

    /// Returns the context bytes/fork_digest corresponding to the genesis fork version.
    pub fn genesis_context_bytes(&self) -> [u8; 4] {
        self.epoch_to_forks
            .first_key_value()
            .expect("must contain genesis epoch")
            .1
            .fork_digest
    }

    /// Returns the fork type given the context bytes/fork_digest.
    /// Returns `None` if context bytes doesn't correspond to any valid `ForkName`.
    pub fn get_fork_from_context_bytes(&self, context: [u8; 4]) -> Option<&ForkName> {
        self.epoch_to_forks
            .values()
            .find(|fork| fork.fork_digest == context)
            .map(|fork| &fork.fork_name)
    }

    /// Returns the context bytes/fork_digest corresponding to an epoch.
    /// See [`ChainSpec::compute_fork_digest`]
    pub fn context_bytes(&self, epoch: Epoch) -> [u8; 4] {
        self.epoch_to_forks
            .range(..=epoch)
            .next_back()
            .expect("should match at least genesis epoch")
            .1
            .fork_digest
    }

    /// Returns all `fork_digest`s that are currently in the `ForkContext` object.
    pub fn all_fork_digests(&self) -> Vec<[u8; 4]> {
        self.epoch_to_forks
            .values()
            .map(|fork| fork.fork_digest)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;
    use crate::chain_spec::{BlobParameters, BlobSchedule};

    type E = MainnetEthSpec;

    fn make_chain_spec() -> ChainSpec {
        let blob_parameters = vec![
            BlobParameters {
                epoch: Epoch::new(6),
                max_blobs_per_block: 12,
            },
            BlobParameters {
                epoch: Epoch::new(50),
                max_blobs_per_block: 24,
            },
            BlobParameters {
                epoch: Epoch::new(100),
                max_blobs_per_block: 48,
            },
        ];

        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(1));
        spec.bellatrix_fork_epoch = Some(Epoch::new(2));
        spec.capella_fork_epoch = Some(Epoch::new(3));
        spec.deneb_fork_epoch = Some(Epoch::new(4));
        spec.electra_fork_epoch = Some(Epoch::new(5));
        spec.fulu_fork_epoch = Some(Epoch::new(6));
        spec.blob_schedule = BlobSchedule::new(blob_parameters);
        spec
    }

    #[test]
    fn test_fork_exists() {
        let spec = make_chain_spec();
        let genesis_root = Hash256::ZERO;
        let current_slot = Slot::new(7);

        let context = ForkContext::new::<E>(current_slot, genesis_root, &spec);

        assert!(context.fork_exists(ForkName::Electra));
        assert!(context.fork_exists(ForkName::Fulu));
    }

    #[test]
    fn test_current_fork_name_and_epoch() {
        let spec = make_chain_spec();
        let electra_epoch = spec.electra_fork_epoch.unwrap();
        let electra_slot = electra_epoch.end_slot(E::slots_per_epoch());
        let genesis_root = Hash256::ZERO;

        let context = ForkContext::new::<E>(electra_slot, genesis_root, &spec);

        assert_eq!(context.current_fork_name(), ForkName::Electra);
        assert_eq!(context.current_fork_epoch(), electra_epoch);
    }

    #[test]
    fn test_next_fork_digest() {
        let spec = make_chain_spec();
        let electra_epoch = spec.electra_fork_epoch.unwrap();
        let electra_slot = electra_epoch.end_slot(E::slots_per_epoch());
        let genesis_root = Hash256::ZERO;

        let context = ForkContext::new::<E>(electra_slot, genesis_root, &spec);

        let next_digest = context.next_fork_digest().unwrap();
        let expected_digest = spec.compute_fork_digest(genesis_root, spec.fulu_fork_epoch.unwrap());
        assert_eq!(next_digest, expected_digest);
    }

    #[test]
    fn test_get_fork_from_context_bytes() {
        let spec = make_chain_spec();
        let genesis_root = Hash256::ZERO;
        let current_slot = Slot::new(0);

        let context = ForkContext::new::<E>(current_slot, genesis_root, &spec);

        let electra_digest = spec.compute_fork_digest(genesis_root, Epoch::new(5));
        assert_eq!(
            context.get_fork_from_context_bytes(electra_digest),
            Some(&ForkName::Electra)
        );

        let invalid_digest = [9, 9, 9, 9];
        assert!(
            context
                .get_fork_from_context_bytes(invalid_digest)
                .is_none()
        );
    }

    #[test]
    fn test_context_bytes() {
        let spec = make_chain_spec();
        let genesis_root = Hash256::ZERO;
        let current_slot = Slot::new(0);

        let context = ForkContext::new::<E>(current_slot, genesis_root, &spec);

        assert_eq!(
            context.context_bytes(Epoch::new(0)),
            spec.compute_fork_digest(genesis_root, Epoch::new(0))
        );

        assert_eq!(
            context.context_bytes(Epoch::new(12)),
            spec.compute_fork_digest(genesis_root, Epoch::new(10))
        );
    }

    #[test]
    fn test_all_fork_digests() {
        let spec = make_chain_spec();
        let genesis_root = Hash256::ZERO;
        let current_slot = Slot::new(20);

        let context = ForkContext::new::<MainnetEthSpec>(current_slot, genesis_root, &spec);

        // Get all enabled fork digests
        let fork_digests = context.all_fork_digests();
        let expected_digest_count = spec.all_digest_epochs().count();

        assert_eq!(fork_digests.len(), expected_digest_count);
    }
}
