//! Provides the `ObservedBlockProducers` struct which allows for rejecting gossip blocks from
//! validators that have already produced a block.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use types::{BeaconBlockRef, Epoch, EthSpec, Hash256, Slot, Unsigned};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The slot of the provided block is prior to finalization and should not have been provided
    /// to this function. This is an internal error.
    FinalizedBlock { slot: Slot, finalized_slot: Slot },
    /// The function to obtain a set index failed, this is an internal error.
    ValidatorIndexTooHigh(u64),
}

#[derive(Eq, Hash, PartialEq, Debug, Default)]
struct ProposalKey {
    slot: Slot,
    proposer: u64,
}

/// Maintains a cache of observed `(block.slot, block.proposer)`.
///
/// The cache supports pruning based upon the finalized epoch. It does not automatically prune, you
/// must call `Self::prune` manually.
///
/// The maximum size of the cache is determined by `slots_since_finality *
/// VALIDATOR_REGISTRY_LIMIT`. This is quite a large size, so it's important that upstream
/// functions only use this cache for blocks with a valid signature. Only allowing valid signed
/// blocks reduces the theoretical maximum size of this cache to `slots_since_finality *
/// active_validator_count`, however in reality that is more like `slots_since_finality *
/// known_distinct_shufflings` which is much smaller.
pub struct ObservedBlockProducers<E: EthSpec> {
    finalized_slot: Slot,
    items: HashMap<ProposalKey, HashSet<Hash256>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedBlockProducers<E> {
    /// Instantiates `Self` with `finalized_slot == 0`.
    fn default() -> Self {
        Self {
            finalized_slot: Slot::new(0),
            items: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

pub enum SeenBlock {
    Duplicate,
    Slashable,
    UniqueNonSlashable,
}

impl SeenBlock {
    pub fn proposer_previously_observed(self) -> bool {
        match self {
            Self::Duplicate | Self::Slashable => true,
            Self::UniqueNonSlashable => false,
        }
    }
    pub fn is_slashable(&self) -> bool {
        matches!(self, Self::Slashable)
    }
}

impl<E: EthSpec> ObservedBlockProducers<E> {
    /// Observe that the `block` was produced by `block.proposer_index` at `block.slot`. This will
    /// update `self` so future calls to it indicate that this block is known.
    ///
    /// The supplied `block` **MUST** be signature verified (see struct-level documentation).
    ///
    /// ## Errors
    ///
    /// - `block.proposer_index` is greater than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `block.slot` is equal to or less than the latest pruned `finalized_slot`.
    pub fn observe_proposal(
        &mut self,
        block_root: Hash256,
        block: BeaconBlockRef<'_, E>,
    ) -> Result<SeenBlock, Error> {
        self.sanitize_block(block)?;

        let key = ProposalKey {
            slot: block.slot(),
            proposer: block.proposer_index(),
        };

        let entry = self.items.entry(key);

        let slashable_proposal = match entry {
            Entry::Occupied(mut occupied_entry) => {
                let block_roots = occupied_entry.get_mut();
                let newly_inserted = block_roots.insert(block_root);

                let is_equivocation = block_roots.len() > 1;

                if is_equivocation {
                    SeenBlock::Slashable
                } else if !newly_inserted {
                    SeenBlock::Duplicate
                } else {
                    SeenBlock::UniqueNonSlashable
                }
            }
            Entry::Vacant(vacant_entry) => {
                let block_roots = HashSet::from([block_root]);
                vacant_entry.insert(block_roots);

                SeenBlock::UniqueNonSlashable
            }
        };

        Ok(slashable_proposal)
    }

    /// Returns `Ok(true)` if the `block` has been observed before, `Ok(false)` if not. Does not
    /// update the cache, so calling this function multiple times will continue to return
    /// `Ok(false)`, until `Self::observe_proposer` is called.
    ///
    /// ## Errors
    ///
    /// - `block.proposer_index` is greater than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `block.slot` is equal to or less than the latest pruned `finalized_slot`.
    pub fn proposer_has_been_observed(
        &self,
        block: BeaconBlockRef<'_, E>,
        block_root: Hash256,
    ) -> Result<SeenBlock, Error> {
        self.sanitize_block(block)?;

        let key = ProposalKey {
            slot: block.slot(),
            proposer: block.proposer_index(),
        };

        if let Some(block_roots) = self.items.get(&key) {
            let block_already_known = block_roots.contains(&block_root);
            let no_prev_known_blocks =
                block_roots.difference(&HashSet::from([block_root])).count() == 0;

            if !no_prev_known_blocks {
                Ok(SeenBlock::Slashable)
            } else if block_already_known {
                Ok(SeenBlock::Duplicate)
            } else {
                Ok(SeenBlock::UniqueNonSlashable)
            }
        } else {
            Ok(SeenBlock::UniqueNonSlashable)
        }
    }

    /// Returns `Ok(())` if the given `block` is sane.
    fn sanitize_block(&self, block: BeaconBlockRef<'_, E>) -> Result<(), Error> {
        if block.proposer_index() >= E::ValidatorRegistryLimit::to_u64() {
            return Err(Error::ValidatorIndexTooHigh(block.proposer_index()));
        }

        let finalized_slot = self.finalized_slot;
        if finalized_slot > 0 && block.slot() <= finalized_slot {
            return Err(Error::FinalizedBlock {
                slot: block.slot(),
                finalized_slot,
            });
        }

        Ok(())
    }

    /// Removes all observations of blocks equal to or earlier than `finalized_slot`.
    ///
    /// Stores `finalized_slot` in `self`, so that `self` will reject any block that has a slot
    /// equal to or less than `finalized_slot`.
    ///
    /// No-op if `finalized_slot == 0`.
    pub fn prune(&mut self, finalized_slot: Slot) {
        if finalized_slot == 0 {
            return;
        }

        self.finalized_slot = finalized_slot;
        self.items.retain(|key, _| key.slot > finalized_slot);
    }

    /// Returns `true` if the given `validator_index` has been stored in `self` at `epoch`.
    ///
    /// This is useful for doppelganger detection.
    pub fn index_seen_at_epoch(&self, validator_index: u64, epoch: Epoch) -> bool {
        self.items.iter().any(|(key, _)| {
            key.slot.epoch(E::slots_per_epoch()) == epoch && key.proposer == validator_index
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{BeaconBlock, MainnetEthSpec};

    type E = MainnetEthSpec;

    fn get_block(slot: u64, proposer: u64) -> BeaconBlock<E> {
        let mut block = BeaconBlock::empty(&E::default_spec());
        *block.slot_mut() = slot.into();
        *block.proposer_index_mut() = proposer;
        block
    }

    #[test]
    fn pruning() {
        let mut cache = ObservedBlockProducers::default();

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 0, "no slots should be present");

        // Slot 0, proposer 0
        let block_a = get_block(0, 0);
        let block_root = block_a.canonical_root();

        assert_eq!(
            cache
                .observe_proposal(block_root, block_a.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(false),
            "can observe proposer, indicates proposer unobserved"
        );

        /*
         * Preconditions.
         */

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        assert_eq!(
            cache
                .items
                .get(&ProposalKey {
                    slot: Slot::new(0),
                    proposer: 0
                })
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune at the genesis slot does nothing.
         */

        cache.prune(Slot::new(0));

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        assert_eq!(
            cache
                .items
                .get(&ProposalKey {
                    slot: Slot::new(0),
                    proposer: 0
                })
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune empties the cache
         */

        cache.prune(E::slots_per_epoch().into());
        assert_eq!(
            cache.finalized_slot,
            Slot::from(E::slots_per_epoch()),
            "finalized slot is updated"
        );
        assert_eq!(cache.items.len(), 0, "no items left");

        /*
         * Check that we can't insert a finalized block
         */

        // First slot of finalized epoch, proposer 0
        let block_b = get_block(E::slots_per_epoch(), 0);
        let block_root_b = block_b.canonical_root();

        assert_eq!(
            cache
                .observe_proposal(block_root_b, block_b.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Err(Error::FinalizedBlock {
                slot: E::slots_per_epoch().into(),
                finalized_slot: E::slots_per_epoch().into(),
            }),
            "cant insert finalized block"
        );

        assert_eq!(cache.items.len(), 0, "block was not added");

        /*
         * Check that we _can_ insert a non-finalized block
         */

        let three_epochs = E::slots_per_epoch() * 3;

        // First slot of finalized epoch, proposer 0
        let block_b = get_block(three_epochs, 0);

        assert_eq!(
            cache
                .observe_proposal(block_root_b, block_b.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(false),
            "can insert non-finalized block"
        );

        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        assert_eq!(
            cache
                .items
                .get(&ProposalKey {
                    slot: Slot::new(three_epochs),
                    proposer: 0
                })
                .expect("the three epochs slot should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        /*
         * Check that a prune doesnt wipe later blocks
         */

        let two_epochs = E::slots_per_epoch() * 2;
        cache.prune(two_epochs.into());

        assert_eq!(
            cache.finalized_slot,
            Slot::from(two_epochs),
            "finalized slot is updated"
        );

        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        assert_eq!(
            cache
                .items
                .get(&ProposalKey {
                    slot: Slot::new(three_epochs),
                    proposer: 0
                })
                .expect("the three epochs slot should be present")
                .len(),
            1,
            "only one proposer should be present"
        );
    }

    #[test]
    fn simple_observations() {
        let mut cache = ObservedBlockProducers::default();

        // Slot 0, proposer 0
        let block_a = get_block(0, 0);
        let block_root_a = block_a.canonical_root();

        assert_eq!(
            cache
                .proposer_has_been_observed(block_a.to_ref(), block_a.canonical_root())
                .map(|x| x.proposer_previously_observed()),
            Ok(false),
            "no observation in empty cache"
        );
        assert_eq!(
            cache
                .observe_proposal(block_root_a, block_a.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(false),
            "can observe proposer, indicates proposer unobserved"
        );
        assert_eq!(
            cache
                .proposer_has_been_observed(block_a.to_ref(), block_a.canonical_root())
                .map(|x| x.proposer_previously_observed()),
            Ok(true),
            "observed block is indicated as true"
        );
        assert_eq!(
            cache
                .observe_proposal(block_root_a, block_a.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(true),
            "observing again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 1, "only one slot should be present");
        assert_eq!(
            cache
                .items
                .get(&ProposalKey {
                    slot: Slot::new(0),
                    proposer: 0
                })
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present"
        );

        // Slot 1, proposer 0
        let block_b = get_block(1, 0);
        let block_root_b = block_b.canonical_root();

        assert_eq!(
            cache
                .proposer_has_been_observed(block_b.to_ref(), block_b.canonical_root())
                .map(|x| x.proposer_previously_observed()),
            Ok(false),
            "no observation for new slot"
        );
        assert_eq!(
            cache
                .observe_proposal(block_root_b, block_b.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(false),
            "can observe proposer for new slot, indicates proposer unobserved"
        );
        assert_eq!(
            cache
                .proposer_has_been_observed(block_b.to_ref(), block_b.canonical_root())
                .map(|x| x.proposer_previously_observed()),
            Ok(true),
            "observed block in slot 1 is indicated as true"
        );
        assert_eq!(
            cache
                .observe_proposal(block_root_b, block_b.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(true),
            "observing slot 1 again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 2, "two slots should be present");
        assert_eq!(
            cache
                .items
                .get(&ProposalKey {
                    slot: Slot::new(0),
                    proposer: 0
                })
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present in slot 0"
        );
        assert_eq!(
            cache
                .items
                .get(&ProposalKey {
                    slot: Slot::new(1),
                    proposer: 0
                })
                .expect("slot zero should be present")
                .len(),
            1,
            "only one proposer should be present in slot 1"
        );

        // Slot 0, proposer 1
        let block_c = get_block(0, 1);
        let block_root_c = block_c.canonical_root();

        assert_eq!(
            cache
                .proposer_has_been_observed(block_c.to_ref(), block_c.canonical_root())
                .map(|x| x.proposer_previously_observed()),
            Ok(false),
            "no observation for new proposer"
        );
        assert_eq!(
            cache
                .observe_proposal(block_root_c, block_c.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(false),
            "can observe new proposer, indicates proposer unobserved"
        );
        assert_eq!(
            cache
                .proposer_has_been_observed(block_c.to_ref(), block_c.canonical_root())
                .map(|x| x.proposer_previously_observed()),
            Ok(true),
            "observed new proposer block is indicated as true"
        );
        assert_eq!(
            cache
                .observe_proposal(block_root_c, block_c.to_ref())
                .map(SeenBlock::proposer_previously_observed),
            Ok(true),
            "observing new proposer again indicates true"
        );

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 3, "three slots should be present");
        assert_eq!(
            cache
                .items
                .iter()
                .filter(|(k, _)| k.slot == cache.finalized_slot)
                .count(),
            2,
            "two proposers should be present in slot 0"
        );
        assert_eq!(
            cache
                .items
                .iter()
                .filter(|(k, _)| k.slot == Slot::new(1))
                .count(),
            1,
            "only one proposer should be present in slot 1"
        );
    }
}
