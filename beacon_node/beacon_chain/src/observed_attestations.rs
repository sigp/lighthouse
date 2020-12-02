//! Provides an `ObservedAttestations` struct which allows us to reject aggregated attestations if
//! we've already seen the aggregated attestation.

use std::collections::HashSet;
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{Attestation, EthSpec, Hash256, Slot};

/// As a DoS protection measure, the maximum number of distinct `Attestations` that will be
/// recorded for each slot.
///
/// Currently this is set to ~524k. If we say that each entry is 40 bytes (Hash256 (32 bytes) + an
/// 8 byte hash) then this comes to about 20mb per slot. If we're storing 34 of these slots, then
/// we're at 680mb. This is a lot of memory usage, but probably not a show-stopper for most
/// reasonable hardware.
///
/// Upstream conditions should strongly restrict the amount of attestations that can show up in
/// this pool. The maximum size with respect to upstream restrictions is more likely on the order
/// of the number of validators.
const MAX_OBSERVATIONS_PER_SLOT: usize = 1 << 19; // 524,288

#[derive(Debug, PartialEq)]
pub enum ObserveOutcome {
    /// This attestation was already known.
    AlreadyKnown,
    /// This was the first time this attestation was observed.
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

/// A `HashSet` that contains entries related to some `Slot`.
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

    /// Store the attestation in self so future observations recognise its existence.
    pub fn observe_attestation<E: EthSpec>(
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

    /// Indicates if `a` has been observed before.
    pub fn is_known<E: EthSpec>(&self, a: &Attestation<E>, root: Hash256) -> Result<bool, Error> {
        if a.data.slot != self.slot {
            return Err(Error::IncorrectSlot {
                expected: self.slot,
                attestation: a.data.slot,
            });
        }

        Ok(self.set.contains(&root))
    }

    /// The number of observed attestations in `self`.
    pub fn len(&self) -> usize {
        self.set.len()
    }
}

/// Stores the roots of `Attestation` objects for some number of `Slots`, so we can determine if
/// these have previously been seen on the network.
pub struct ObservedAttestations<E: EthSpec> {
    lowest_permissible_slot: Slot,
    sets: Vec<SlotHashSet>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ObservedAttestations<E> {
    fn default() -> Self {
        Self {
            lowest_permissible_slot: Slot::new(0),
            sets: vec![],
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ObservedAttestations<E> {
    /// Store the root of `a` in `self`.
    ///
    /// `root` must equal `a.tree_hash_root()`.
    pub fn observe_attestation(
        &mut self,
        a: &Attestation<E>,
        root_opt: Option<Hash256>,
    ) -> Result<ObserveOutcome, Error> {
        let index = self.get_set_index(a.data.slot)?;
        let root = root_opt.unwrap_or_else(|| a.tree_hash_root());

        self.sets
            .get_mut(index)
            .ok_or(Error::InvalidSetIndex(index))
            .and_then(|set| set.observe_attestation(a, root))
    }

    /// Check to see if the `root` of `a` is in self.
    ///
    /// `root` must equal `a.tree_hash_root()`.
    pub fn is_known(&mut self, a: &Attestation<E>, root: Hash256) -> Result<bool, Error> {
        let index = self.get_set_index(a.data.slot)?;

        self.sets
            .get(index)
            .ok_or(Error::InvalidSetIndex(index))
            .and_then(|set| set.is_known(a, root))
    }

    /// The maximum number of slots that attestations are stored for.
    fn max_capacity(&self) -> u64 {
        // We add `2` in order to account for one slot either side of the range due to
        // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
        E::slots_per_epoch() + 2
    }

    /// Removes any attestations with a slot lower than `current_slot` and bars any future
    /// attestations with a slot lower than `current_slot - SLOTS_RETAINED`.
    pub fn prune(&mut self, current_slot: Slot) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_slot = current_slot - (self.max_capacity() - 1);

        self.sets.retain(|set| set.slot >= lowest_permissible_slot);

        self.lowest_permissible_slot = lowest_permissible_slot;
    }

    /// Returns the index of `self.set` that matches `slot`.
    ///
    /// If there is no existing set for this slot one will be created. If `self.sets.len() >=
    /// Self::max_capacity()`, the set with the lowest slot will be replaced.
    fn get_set_index(&mut self, slot: Slot) -> Result<usize, Error> {
        let lowest_permissible_slot = self.lowest_permissible_slot;

        if slot < lowest_permissible_slot {
            return Err(Error::SlotTooLow {
                slot,
                lowest_permissible_slot,
            });
        }

        // Prune the pool if this attestation indicates that the current slot has advanced.
        if lowest_permissible_slot + self.max_capacity() < slot + 1 {
            self.prune(slot)
        }

        if let Some(index) = self.sets.iter().position(|set| set.slot == slot) {
            return Ok(index);
        }

        // To avoid re-allocations, try and determine a rough initial capacity for the new set
        // by obtaining the mean size of all items in earlier epoch.
        let (count, sum) = self
            .sets
            .iter()
            // Only include slots that are less than the given slot in the average. This should
            // generally avoid including recent slots that are still "filling up".
            .filter(|set| set.slot < slot)
            .map(|set| set.len())
            .fold((0, 0), |(count, sum), len| (count + 1, sum + len));
        // If we are unable to determine an average, just use 128 as it's the target committee
        // size for the mainnet spec. This is perhaps a little wasteful for the minimal spec,
        // but considering it's approx. 128 * 32 bytes we're not wasting much.
        let initial_capacity = sum.checked_div(count).unwrap_or(128);

        if self.sets.len() < self.max_capacity() as usize || self.sets.is_empty() {
            let index = self.sets.len();
            self.sets.push(SlotHashSet::new(slot, initial_capacity));
            return Ok(index);
        }

        let index = self
            .sets
            .iter()
            .enumerate()
            .min_by_key(|(_i, set)| set.slot)
            .map(|(i, _set)| i)
            .expect("sets cannot be empty due to previous .is_empty() check");

        self.sets[index] = SlotHashSet::new(slot, initial_capacity);

        Ok(index)
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
mod tests {
    use super::*;
    use tree_hash::TreeHash;
    use types::{test_utils::test_random_instance, Hash256};

    type E = types::MainnetEthSpec;

    const NUM_ELEMENTS: usize = 8;

    fn get_attestation(slot: Slot, beacon_block_root: u64) -> Attestation<E> {
        let mut a: Attestation<E> = test_random_instance();
        a.data.slot = slot;
        a.data.beacon_block_root = Hash256::from_low_u64_be(beacon_block_root);
        a
    }

    fn single_slot_test(store: &mut ObservedAttestations<E>, slot: Slot) {
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
                store.observe_attestation(a, None),
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
                store.observe_attestation(a, Some(a.tree_hash_root())),
                Ok(ObserveOutcome::AlreadyKnown),
                "should acknowledge an existing attestation"
            );
        }
    }

    #[test]
    fn single_slot() {
        let mut store = ObservedAttestations::default();

        single_slot_test(&mut store, Slot::new(0));

        assert_eq!(store.sets.len(), 1, "should have a single set stored");
        assert_eq!(
            store.sets[0].len(),
            NUM_ELEMENTS,
            "set should have NUM_ELEMENTS elements"
        );
    }

    #[test]
    fn mulitple_contiguous_slots() {
        let mut store = ObservedAttestations::default();
        let max_cap = store.max_capacity();

        for i in 0..max_cap * 3 {
            let slot = Slot::new(i);

            single_slot_test(&mut store, slot);

            /*
             * Ensure that the number of sets is correct.
             */

            if i < max_cap {
                assert_eq!(
                    store.sets.len(),
                    i as usize + 1,
                    "should have a {} sets stored",
                    i + 1
                );
            } else {
                assert_eq!(
                    store.sets.len(),
                    max_cap as usize,
                    "should have max_capacity sets stored"
                );
            }

            /*
             * Ensure that each set contains the correct number of elements.
             */

            for set in &store.sets[..] {
                assert_eq!(
                    set.len(),
                    NUM_ELEMENTS,
                    "each store should have NUM_ELEMENTS elements"
                )
            }

            /*
             *  Ensure that all the sets have the expected slots
             */

            let mut store_slots = store.sets.iter().map(|set| set.slot).collect::<Vec<_>>();

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
        let mut store = ObservedAttestations::default();
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

            single_slot_test(&mut store, slot);

            /*
             * Ensure that each set contains the correct number of elements.
             */

            for set in &store.sets[..] {
                assert_eq!(
                    set.len(),
                    NUM_ELEMENTS,
                    "each store should have NUM_ELEMENTS elements"
                )
            }

            /*
             *  Ensure that all the sets have the expected slots
             */

            let mut store_slots = store.sets.iter().map(|set| set.slot).collect::<Vec<_>>();

            store_slots.sort_unstable();

            assert!(
                store_slots.len() <= store.max_capacity() as usize,
                "store size should not exceed max"
            );

            let lowest = store.lowest_permissible_slot.as_u64();
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
