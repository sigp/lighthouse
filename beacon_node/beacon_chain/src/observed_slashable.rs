//! Provides the `ObservedSlashable` struct which tracks slashable messages seen in
//! gossip or via RPC. Useful in supporting `broadcast_validation` in the Beacon API.

use crate::observed_block_producers::Error;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use types::{EthSpec, Hash256, Slot, Unsigned};

#[derive(Eq, Hash, PartialEq, Debug, Default)]
pub struct ProposalKey {
    pub slot: Slot,
    pub proposer: u64,
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
pub struct ObservedSlashable<E: EthSpec> {
    finalized_slot: Slot,
    items: HashMap<ProposalKey, HashSet<Hash256>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedSlashable<E> {
    /// Instantiates `Self` with `finalized_slot == 0`.
    fn default() -> Self {
        Self {
            finalized_slot: Slot::new(0),
            items: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ObservedSlashable<E> {
    /// Observe that the `header` was produced by `header.proposer_index` at `header.slot`. This will
    /// update `self` so future calls to it indicate that this block is known.
    ///
    /// The supplied `block` **MUST** be signature verified (see struct-level documentation).
    ///
    /// ## Errors
    ///
    /// - `header.proposer_index` is greater than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `header.slot` is equal to or less than the latest pruned `finalized_slot`.
    pub fn observe_slashable(
        &mut self,
        slot: Slot,
        proposer_index: u64,
        block_root: Hash256,
    ) -> Result<(), Error> {
        self.sanitize_header(slot, proposer_index)?;

        let key = ProposalKey {
            slot,
            proposer: proposer_index,
        };

        let entry = self.items.entry(key);

        match entry {
            Entry::Occupied(mut occupied_entry) => {
                let block_roots = occupied_entry.get_mut();
                block_roots.insert(block_root);
            }
            Entry::Vacant(vacant_entry) => {
                let block_roots = HashSet::from([block_root]);
                vacant_entry.insert(block_roots);
            }
        }

        Ok(())
    }

    /// Returns `Ok(true)` if the `block_root` is slashable, `Ok(false)` if not. Does not
    /// update the cache, so calling this function multiple times will continue to return
    /// `Ok(false)`, until `Self::observe_proposer` is called.
    ///
    /// ## Errors
    ///
    /// - `proposer_index` is greater than `VALIDATOR_REGISTRY_LIMIT`.
    /// - `slot` is equal to or less than the latest pruned `finalized_slot`.
    pub fn is_slashable(
        &self,
        slot: Slot,
        proposer_index: u64,
        block_root: Hash256,
    ) -> Result<bool, Error> {
        self.sanitize_header(slot, proposer_index)?;

        let key = ProposalKey {
            slot,
            proposer: proposer_index,
        };

        if let Some(block_roots) = self.items.get(&key) {
            let no_prev_known_blocks =
                block_roots.difference(&HashSet::from([block_root])).count() == 0;

            Ok(!no_prev_known_blocks)
        } else {
            Ok(false)
        }
    }

    /// Returns `Ok(())` if the given `header` is sane.
    fn sanitize_header(&self, slot: Slot, proposer_index: u64) -> Result<(), Error> {
        if proposer_index >= E::ValidatorRegistryLimit::to_u64() {
            return Err(Error::ValidatorIndexTooHigh(proposer_index));
        }

        let finalized_slot = self.finalized_slot;
        if finalized_slot > 0 && slot <= finalized_slot {
            return Err(Error::FinalizedBlock {
                slot,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{BeaconBlock, Graffiti, MainnetEthSpec};

    type E = MainnetEthSpec;

    fn get_block(slot: u64, proposer: u64) -> BeaconBlock<E> {
        let mut block = BeaconBlock::empty(&E::default_spec());
        *block.slot_mut() = slot.into();
        *block.proposer_index_mut() = proposer;
        block
    }

    #[test]
    fn pruning() {
        let mut cache = ObservedSlashable::<E>::default();

        assert_eq!(cache.finalized_slot, 0, "finalized slot is zero");
        assert_eq!(cache.items.len(), 0, "no slots should be present");

        // Slot 0, proposer 0
        let block_a = get_block(0, 0);
        let block_root = block_a.canonical_root();

        assert_eq!(
            cache.observe_slashable(block_a.slot(), block_a.proposer_index(), block_root),
            Ok(()),
            "can observe proposer"
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
            "only one block root should be present"
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
            cache.observe_slashable(block_b.slot(), block_b.proposer_index(), block_root_b),
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
            cache.observe_slashable(block_b.slot(), block_b.proposer_index(), block_root_b),
            Ok(()),
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
            "only one block root should be present"
        );
    }

    #[test]
    fn simple_observations() {
        let mut cache = ObservedSlashable::<E>::default();

        // Slot 0, proposer 0
        let block_a = get_block(0, 0);
        let block_root_a = block_a.canonical_root();

        assert_eq!(
            cache.is_slashable(
                block_a.slot(),
                block_a.proposer_index(),
                block_a.canonical_root()
            ),
            Ok(false),
            "no observation in empty cache"
        );
        assert_eq!(
            cache.observe_slashable(block_a.slot(), block_a.proposer_index(), block_root_a),
            Ok(()),
            "can observe proposer"
        );
        assert_eq!(
            cache.is_slashable(
                block_a.slot(),
                block_a.proposer_index(),
                block_a.canonical_root()
            ),
            Ok(false),
            "observed but unslashed block"
        );
        assert_eq!(
            cache.observe_slashable(block_a.slot(), block_a.proposer_index(), block_root_a),
            Ok(()),
            "observing again"
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
            "only one block root should be present"
        );

        // Slot 1, proposer 0
        let block_b = get_block(1, 0);
        let block_root_b = block_b.canonical_root();

        assert_eq!(
            cache.is_slashable(
                block_b.slot(),
                block_b.proposer_index(),
                block_b.canonical_root()
            ),
            Ok(false),
            "not slashable for new slot"
        );
        assert_eq!(
            cache.observe_slashable(block_b.slot(), block_b.proposer_index(), block_root_b),
            Ok(()),
            "can observe proposer for new slot"
        );
        assert_eq!(
            cache.is_slashable(
                block_b.slot(),
                block_b.proposer_index(),
                block_b.canonical_root()
            ),
            Ok(false),
            "observed but not slashable block in slot 1"
        );
        assert_eq!(
            cache.observe_slashable(block_b.slot(), block_b.proposer_index(), block_root_b),
            Ok(()),
            "observing slot 1 again"
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
            "only one block root should be present in slot 0"
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
            "only one block root should be present in slot 1"
        );

        // Slot 0, proposer 1
        let block_c = get_block(0, 1);
        let block_root_c = block_c.canonical_root();

        assert_eq!(
            cache.is_slashable(
                block_c.slot(),
                block_c.proposer_index(),
                block_c.canonical_root()
            ),
            Ok(false),
            "not slashable due to new proposer"
        );
        assert_eq!(
            cache.observe_slashable(block_c.slot(), block_c.proposer_index(), block_root_c),
            Ok(()),
            "can observe new proposer, indicates proposer unobserved"
        );
        assert_eq!(
            cache.is_slashable(
                block_c.slot(),
                block_c.proposer_index(),
                block_c.canonical_root()
            ),
            Ok(false),
            "not slashable due to new proposer"
        );
        assert_eq!(
            cache.observe_slashable(block_c.slot(), block_c.proposer_index(), block_root_c),
            Ok(()),
            "observing new proposer again"
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

        // Slot 0, proposer 1 (again)
        let mut block_d = get_block(0, 1);
        *block_d.body_mut().graffiti_mut() = Graffiti::from(*b"this is slashable               ");
        let block_root_d = block_d.canonical_root();

        assert_eq!(
            cache.is_slashable(
                block_d.slot(),
                block_d.proposer_index(),
                block_d.canonical_root()
            ),
            Ok(true),
            "slashable due to new proposer"
        );
        assert_eq!(
            cache.observe_slashable(block_d.slot(), block_d.proposer_index(), block_root_d),
            Ok(()),
            "can observe new proposer, indicates proposer unobserved"
        );
    }
}
