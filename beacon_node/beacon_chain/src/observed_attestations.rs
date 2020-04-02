use parking_lot::RwLock;
use std::collections::HashSet;
use std::marker::PhantomData;
use types::{Attestation, EthSpec, Hash256, Slot};

/// The number of slots that will be stored in the pool.
///
/// For example, if `SLOTS_RETAINED == 3` and the pool is pruned at slot `6`, then all attestations
/// at slots less than `4` will be dropped and any future attestation with a slot less than `4`
/// will be refused.
const SLOTS_RETAINED: usize = 3;

/// As a DoS protection measure, the maximum number of distinct `Attestations` that will be
/// recorded for each slot.
///
/// Currently this is set to ~524k. If we say that each entry is 40 bytes (Hash256 (32 bytes) + an
/// 8 byte hash) then this comes to about 20mb per slot. If we're storing 34 of these slots, then
/// we're at 680mb. This is a lot of memory usage, but probably not a show-stopper for most
/// reasonable hardware.
const MAX_OBSERVATIONS_PER_SLOT: usize = 1 << 19; // 524,288

#[derive(Debug, PartialEq)]
pub enum ObserveOutcome {
    AlreadyKnown,
    New,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotTooLow {
        slot: Slot,
        lowest_permissible_slot: Slot,
    },
    /// The function to obtain a set index failed, this is an internal error.
    InvalidSetIndex(usize),
    /// We have reached the maximum number of unique `Attestation` that can be observed in a slot.
    /// This is a DoS protection function.
    ReachedMaxObservationsPerSlot(usize),
    IncorrectSlot {
        expected: Slot,
        attestation: Slot,
    },
}

struct SlotHashSet {
    set: HashSet<Hash256>,
    slot: Slot,
}

impl SlotHashSet {
    pub fn new(slot: Slot, initial_capacity: usize) -> Self {
        Self {
            slot,
            set: HashSet::with_capacity(initial_capacity),
        }
    }

    pub fn observe<E: EthSpec>(
        &mut self,
        a: &Attestation<E>,
        root: Hash256,
    ) -> Result<ObserveOutcome, Error> {
        if a.data.slot != self.slot {
            return Err(Error::IncorrectSlot {
                expected: self.slot,
                attestation: a.data.slot,
            });
        }

        if self.set.contains(&root) {
            Ok(ObserveOutcome::AlreadyKnown)
        } else {
            // Here we check to see if this slot has reached the maximum observation count.
            //
            // The resulting behaviour is that we are no longer able to successfully observe new
            // attestations, however we will continue to return `is_known` values. We could also
            // disable `is_known`, however then we would stop forwarding attestations across the
            // gossip network and I think that this is a worse case than sending some invalid ones.
            // The underlying libp2p network is responsible for removing duplicate messages, so
            // this doesn't risk a broadcast loop.
            if self.set.len() >= MAX_OBSERVATIONS_PER_SLOT {
                return Err(Error::ReachedMaxObservationsPerSlot(
                    MAX_OBSERVATIONS_PER_SLOT,
                ));
            }

            self.set.insert(root);

            Ok(ObserveOutcome::New)
        }
    }

    pub fn is_known<E: EthSpec>(&self, a: &Attestation<E>, root: Hash256) -> Result<bool, Error> {
        if a.data.slot != self.slot {
            return Err(Error::IncorrectSlot {
                expected: self.slot,
                attestation: a.data.slot,
            });
        }

        Ok(self.set.contains(&root))
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }
}

pub struct ObservedAttestations<E: EthSpec> {
    lowest_permissible_slot: RwLock<Slot>,
    sets: RwLock<Vec<SlotHashSet>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedAttestations<E> {
    fn default() -> Self {
        Self {
            lowest_permissible_slot: RwLock::new(Slot::new(0)),
            sets: RwLock::new(vec![]),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ObservedAttestations<E> {
    pub fn observe(&self, a: &Attestation<E>, root: Hash256) -> Result<ObserveOutcome, Error> {
        let index = self.get_set_index(a.data.slot)?;

        self.sets
            .write()
            .get_mut(index)
            .ok_or_else(|| Error::InvalidSetIndex(index))
            .and_then(|set| set.observe(a, root))
    }

    pub fn is_known(&self, a: &Attestation<E>, root: Hash256) -> Result<bool, Error> {
        let index = self.get_set_index(a.data.slot)?;

        self.sets
            .read()
            .get(index)
            .ok_or_else(|| Error::InvalidSetIndex(index))
            .and_then(|set| set.is_known(a, root))
    }

    fn max_capacity(&self) -> u64 {
        // We add `2` in order to account for one slot either side of the range due to
        // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
        E::slots_per_epoch() + 2
    }

    /// Removes any attestations with a slot lower than `current_slot` and bars any future
    /// attestations with a slot lower than `current_slot - SLOTS_RETAINED`.
    pub fn prune(&self, current_slot: Slot) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_slot = current_slot - (self.max_capacity() - 1);

        self.sets
            .write()
            .retain(|set| set.slot >= lowest_permissible_slot);

        *self.lowest_permissible_slot.write() = lowest_permissible_slot;
    }

    /// Returns the index of `self.set` that matches `slot`.
    ///
    /// If there is no existing set for this slot one will be created. If `self.sets.len() >=
    /// Self::max_capacity()`, the set with the lowest slot will be replaced.
    fn get_set_index(&self, slot: Slot) -> Result<usize, Error> {
        let lowest_permissible_slot: Slot = *self.lowest_permissible_slot.read();

        if slot < lowest_permissible_slot {
            return Err(Error::SlotTooLow {
                slot,
                lowest_permissible_slot,
            });
        }

        // Prune the pool if this attestation indicates that the current slot has advanced.
        if (lowest_permissible_slot + self.max_capacity()) < slot + 1 {
            self.prune(slot)
        }

        let mut sets = self.sets.write();

        if let Some(index) = sets.iter().position(|set| set.slot == slot) {
            return Ok(index);
        }

        // To avoid re-allocations, try and determine a rough initial capacity for the new set by
        // obtaining the mean size of all sets in earlier slots.
        let initial_capacity = sets
            .iter()
            // Only include slots that are less than the given slot in the average. This should
            // generally avoid including recent slots that are still "filling up".
            .filter(|set| set.slot < slot)
            .map(|set| set.len())
            .sum::<usize>()
            .checked_div(sets.len())
            // If we are unable to determine an average, just use 128 as it's the target committee
            // size for the mainnet spec. This is perhaps a little wasteful for the minimal spec,
            // but considering it's approx. 128 * 32 bytes we're not wasting much.
            .unwrap_or_else(|| 128);

        if sets.len() < self.max_capacity() as usize || sets.is_empty() {
            let index = sets.len();
            sets.push(SlotHashSet::new(slot, initial_capacity));
            return Ok(index);
        }

        let index = sets
            .iter()
            .enumerate()
            .min_by_key(|(_i, set)| set.slot)
            .map(|(i, _set)| i)
            .expect("sets cannot be empty due to previous .is_empty() check");

        sets[index] = SlotHashSet::new(slot, initial_capacity);

        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::BitList;
    use tree_hash::TreeHash;
    use types::{
        test_utils::{generate_deterministic_keypair, test_random_instance},
        Fork, Hash256,
    };

    type E = types::MainnetEthSpec;

    const NUM_ELEMENTS: usize = 8;

    fn get_attestation(slot: Slot, beacon_block_root: u64) -> Attestation<E> {
        let mut a: Attestation<E> = test_random_instance();
        a.data.slot = slot;
        a.data.beacon_block_root = Hash256::from_low_u64_be(beacon_block_root);
        a
    }

    fn single_slot_test(store: &ObservedAttestations<E>, slot: Slot) {
        let attestations = (0..NUM_ELEMENTS as u64)
            .map(|i| get_attestation(slot, i))
            .collect::<Vec<_>>();

        for a in &attestations {
            assert_eq!(
                store.is_known(a, a.tree_hash_root()),
                Ok(false),
                "should indicate an unknown attestation is unknown"
            );
            assert_eq!(
                store.observe(a, a.tree_hash_root()),
                Ok(ObserveOutcome::New),
                "should observe new attestation"
            );
        }

        for a in &attestations {
            assert_eq!(
                store.is_known(a, a.tree_hash_root()),
                Ok(true),
                "should indicate a known attestation is known"
            );
            assert_eq!(
                store.observe(a, a.tree_hash_root()),
                Ok(ObserveOutcome::AlreadyKnown),
                "should acknowledge an existing attestation"
            );
        }
    }

    #[test]
    fn single_slot() {
        let store = ObservedAttestations::default();

        single_slot_test(&store, Slot::new(0));

        assert_eq!(
            store.sets.read().len(),
            1,
            "should have a single set stored"
        );
        assert_eq!(
            store.sets.read()[0].len(),
            NUM_ELEMENTS,
            "set should have NUM_ELEMENTS elements"
        );
    }

    #[test]
    fn mulitple_contiguous_slots() {
        let store = ObservedAttestations::default();
        let max_cap = store.max_capacity();

        for i in 0..max_cap * 3 {
            let slot = Slot::new(i);

            single_slot_test(&store, slot);

            /*
             * Ensure that the number of sets is correct.
             */

            if i < max_cap {
                assert_eq!(
                    store.sets.read().len(),
                    i as usize + 1,
                    "should have a {} sets stored",
                    i + 1
                );
            } else {
                assert_eq!(
                    store.sets.read().len(),
                    max_cap as usize,
                    "should have max_capacity sets stored"
                );
            }

            /*
             * Ensure that each set contains the correct number of elements.
             */

            for set in &store.sets.read()[..] {
                assert_eq!(
                    set.len(),
                    NUM_ELEMENTS,
                    "each store should have NUM_ELEMENTS elements"
                )
            }

            /*
             *  Ensure that all the sets have the expected slots
             */

            let mut store_slots = store
                .sets
                .read()
                .iter()
                .map(|set| set.slot)
                .collect::<Vec<_>>();

            assert!(
                store_slots.len() <= store.max_capacity() as usize,
                "store size should not exceed max"
            );

            store_slots.sort_unstable();

            let expected_slots = (i.saturating_sub(max_cap - 1)..=i)
                .map(Slot::new)
                .collect::<Vec<_>>();

            assert_eq!(expected_slots, store_slots, "should have expected slots");
        }
    }

    #[test]
    fn mulitple_non_contiguous_slots() {
        let store = ObservedAttestations::default();
        let max_cap = store.max_capacity();

        let to_skip = vec![1_u64, 2, 3, 5, 6, 29, 30, 31, 32, 64];
        let slots = (0..max_cap * 3)
            .into_iter()
            .filter(|i| !to_skip.contains(i))
            .collect::<Vec<_>>();

        for &i in &slots {
            if to_skip.contains(&i) {
                continue;
            }

            let slot = Slot::from(i);

            single_slot_test(&store, slot);

            /*
             * Ensure that each set contains the correct number of elements.
             */

            for set in &store.sets.read()[..] {
                assert_eq!(
                    set.len(),
                    NUM_ELEMENTS,
                    "each store should have NUM_ELEMENTS elements"
                )
            }

            /*
             *  Ensure that all the sets have the expected slots
             */

            let mut store_slots = store
                .sets
                .read()
                .iter()
                .map(|set| set.slot)
                .collect::<Vec<_>>();

            store_slots.sort_unstable();

            assert!(
                store_slots.len() <= store.max_capacity() as usize,
                "store size should not exceed max"
            );

            let lowest = store.lowest_permissible_slot.read().as_u64();
            let highest = slot.as_u64();
            let expected_slots = (lowest..=highest)
                .filter(|i| !to_skip.contains(i))
                .map(Slot::new)
                .collect::<Vec<_>>();

            assert_eq!(
                expected_slots,
                &store_slots[..],
                "should have expected slots"
            );
        }
    }
}
