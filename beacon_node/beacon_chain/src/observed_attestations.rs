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
            if self.set.len() >= MAX_OBSERVATIONS_PER_SLOT {
                return Err(Error::ReachedMaxObservationsPerSlot(
                    MAX_OBSERVATIONS_PER_SLOT,
                ));
            }

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
    pub fn observe(&mut self, a: &Attestation<E>, root: Hash256) -> Result<ObserveOutcome, Error> {
        let index = self.get_set_index(a.data.slot)?;

        self.sets
            .write()
            .get(index)
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

    fn max_capacity() -> u64 {
        // We add `2` in order to account for one slot either side of the range due to
        // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
        E::slots_per_epoch() + 2
    }

    /// Removes any attestations with a slot lower than `current_slot` and bars any future
    /// attestations with a slot lower than `current_slot - SLOTS_RETAINED`.
    pub fn prune(&self, current_slot: Slot) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_slot = current_slot - Self::max_capacity();

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

        if sets.len() < Self::max_capacity() as usize || sets.is_empty() {
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
    use types::{
        test_utils::{generate_deterministic_keypair, test_random_instance},
        Fork, Hash256,
    };

    type E = types::MainnetEthSpec;

    fn get_attestation(slot: Slot, beacon_block_root: u64) -> Attestation<E> {
        let mut a: Attestation<E> = test_random_instance();
        a.data.slot = slot;
        a.data.beacon_block_root = Hash256::from_low_u64_be(beacon_block_root);
        a
    }

    #[test]
    fn single_attestation() {
        let mut a = get_attestation(Slot::new(0));

        let pool = ObservedAttestations::default();

        assert_eq!(
            pool.insert(&a),
            Err(Error::NoAggregationBitsSet),
            "should not accept attestation without any signatures"
        );

        sign(&mut a, 0);

        assert_eq!(
            pool.insert(&a),
            Ok(InsertOutcome::NewAttestationData { committee_index: 0 }),
            "should accept new attestation"
        );
        assert_eq!(
            pool.insert(&a),
            Ok(InsertOutcome::SignatureAlreadyKnown { committee_index: 0 }),
            "should acknowledge duplicate signature"
        );

        let retrieved = pool
            .get(&a.data)
            .expect("should not error while getting attestation")
            .expect("should get an attestation");
        assert_eq!(
            retrieved, a,
            "retrieved attestation should equal the one inserted"
        );

        sign(&mut a, 1);

        assert_eq!(
            pool.insert(&a),
            Err(Error::MoreThanOneAggregationBitSet(2)),
            "should not accept attestation with multiple signatures"
        );
    }

    #[test]
    fn multiple_attestations() {
        let mut a_0 = get_attestation(Slot::new(0));
        let mut a_1 = a_0.clone();

        sign(&mut a_0, 0);
        sign(&mut a_1, 1);

        let pool = ObservedAttestations::default();

        assert_eq!(
            pool.insert(&a_0),
            Ok(InsertOutcome::NewAttestationData { committee_index: 0 }),
            "should accept a_0"
        );
        assert_eq!(
            pool.insert(&a_1),
            Ok(InsertOutcome::SignatureAggregated { committee_index: 1 }),
            "should accept a_1"
        );

        let retrieved = pool
            .get(&a_0.data)
            .expect("should not error while getting attestation")
            .expect("should get an attestation");

        let mut a_01 = a_0.clone();
        a_01.aggregate(&a_1);

        assert_eq!(
            retrieved, a_01,
            "retrieved attestation should be aggregated"
        );

        /*
         * Throw a different attestation data in there and ensure it isn't aggregated
         */

        let mut a_different = a_0.clone();
        let different_root = Hash256::from_low_u64_be(1337);
        unset_bit(&mut a_different, 0);
        sign(&mut a_different, 2);
        assert!(a_different.data.beacon_block_root != different_root);
        a_different.data.beacon_block_root = different_root;

        assert_eq!(
            pool.insert(&a_different),
            Ok(InsertOutcome::NewAttestationData { committee_index: 2 }),
            "should accept a_different"
        );

        assert_eq!(
            pool.get(&a_0.data)
                .expect("should not error while getting attestation")
                .expect("should get an attestation"),
            retrieved,
            "should not have aggregated different attestation data"
        );
    }

    #[test]
    fn auto_pruning() {
        let mut base = get_attestation(Slot::new(0));
        sign(&mut base, 0);

        let pool = ObservedAttestations::default();

        for i in 0..SLOTS_RETAINED * 2 {
            let slot = Slot::from(i);
            let mut a = base.clone();
            a.data.slot = slot;

            assert_eq!(
                pool.insert(&a),
                Ok(InsertOutcome::NewAttestationData { committee_index: 0 }),
                "should accept new attestation"
            );

            if i < SLOTS_RETAINED {
                let len = i + 1;
                assert_eq!(
                    pool.maps.read().len(),
                    len,
                    "the pool should have length {}",
                    len
                );
            } else {
                assert_eq!(
                    pool.maps.read().len(),
                    SLOTS_RETAINED,
                    "the pool should have length SLOTS_RETAINED"
                );

                let mut pool_slots = pool
                    .maps
                    .read()
                    .iter()
                    .map(|map| map.slot)
                    .collect::<Vec<_>>();

                pool_slots.sort_unstable();

                for (j, pool_slot) in pool_slots.iter().enumerate() {
                    let expected_slot = slot - (SLOTS_RETAINED - 1 - j) as u64;
                    assert_eq!(
                        *pool_slot, expected_slot,
                        "the slot of the map should be {}",
                        expected_slot
                    )
                }
            }
        }
    }

    #[test]
    fn max_attestations() {
        let mut base = get_attestation(Slot::new(0));
        sign(&mut base, 0);

        let pool = ObservedAttestations::default();

        for i in 0..=MAX_ATTESTATIONS_PER_SLOT {
            let mut a = base.clone();
            a.data.beacon_block_root = Hash256::from_low_u64_be(i as u64);

            if i < MAX_ATTESTATIONS_PER_SLOT {
                assert_eq!(
                    pool.insert(&a),
                    Ok(InsertOutcome::NewAttestationData { committee_index: 0 }),
                    "should accept attestation below limit"
                );
            } else {
                assert_eq!(
                    pool.insert(&a),
                    Err(Error::ReachedMaxAttestationsPerSlot(
                        MAX_ATTESTATIONS_PER_SLOT
                    )),
                    "should not accept attestation above limit"
                );
            }
        }
    }
}
