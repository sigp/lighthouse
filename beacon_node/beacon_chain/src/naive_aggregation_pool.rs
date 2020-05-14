use parking_lot::RwLock;
use std::collections::HashMap;
use types::{Attestation, AttestationData, EthSpec, Slot};

/// The number of slots that will be stored in the pool.
///
/// For example, if `SLOTS_RETAINED == 3` and the pool is pruned at slot `6`, then all attestations
/// at slots less than `4` will be dropped and any future attestation with a slot less than `4`
/// will be refused.
const SLOTS_RETAINED: usize = 3;

/// The maximum number of distinct `AttestationData` that will be stored in each slot.
///
/// This is a DoS protection measure.
const MAX_ATTESTATIONS_PER_SLOT: usize = 16_384;

/// Returned upon successfully inserting an attestation into the pool.
#[derive(Debug, PartialEq)]
pub enum InsertOutcome {
    /// The `attestation.data` had not been seen before and was added to the pool.
    NewAttestationData { committee_index: usize },
    /// A validator signature for the given `attestation.data` was already known. No changes were
    /// made.
    SignatureAlreadyKnown { committee_index: usize },
    /// The `attestation.data` was known, but a signature for the given validator was not yet
    /// known. The signature was aggregated into the pool.
    SignatureAggregated { committee_index: usize },
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The given `attestation.data.slot` was too low to be stored. No changes were made.
    SlotTooLow {
        slot: Slot,
        lowest_permissible_slot: Slot,
    },
    /// The given `attestation.aggregation_bits` field was empty.
    NoAggregationBitsSet,
    /// The given `attestation.aggregation_bits` field had more than one signature. The number of
    /// signatures found is included.
    MoreThanOneAggregationBitSet(usize),
    /// We have reached the maximum number of unique `AttestationData` that can be stored in a
    /// slot. This is a DoS protection function.
    ReachedMaxAttestationsPerSlot(usize),
    /// The given `attestation.aggregation_bits` field had a different length to the one currently
    /// stored. This indicates a fairly serious error somewhere in the code that called this
    /// function.
    InconsistentBitfieldLengths,
    /// The given `attestation` was for the incorrect slot. This is an internal error.
    IncorrectSlot { expected: Slot, attestation: Slot },
}

/// A collection of `Attestation` objects, keyed by their `attestation.data`. Enforces that all
/// `attestation` are from the same slot.
struct AggregatedAttestationMap<E: EthSpec> {
    map: HashMap<AttestationData, Attestation<E>>,
}

impl<E: EthSpec> AggregatedAttestationMap<E> {
    /// Create an empty collection with the given `initial_capacity`.
    pub fn new(initial_capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(initial_capacity),
        }
    }

    /// Insert an attestation into `self`, aggregating it into the pool.
    ///
    /// The given attestation (`a`) must only have one signature.
    pub fn insert(&mut self, a: &Attestation<E>) -> Result<InsertOutcome, Error> {
        let set_bits = a
            .aggregation_bits
            .iter()
            .enumerate()
            .filter(|(_i, bit)| *bit)
            .map(|(i, _bit)| i)
            .collect::<Vec<_>>();

        let committee_index = set_bits
            .first()
            .copied()
            .ok_or_else(|| Error::NoAggregationBitsSet)?;

        if set_bits.len() > 1 {
            return Err(Error::MoreThanOneAggregationBitSet(set_bits.len()));
        }

        if let Some(existing_attestation) = self.map.get_mut(&a.data) {
            if existing_attestation
                .aggregation_bits
                .get(committee_index)
                .map_err(|_| Error::InconsistentBitfieldLengths)?
            {
                Ok(InsertOutcome::SignatureAlreadyKnown { committee_index })
            } else {
                existing_attestation.aggregate(a);
                Ok(InsertOutcome::SignatureAggregated { committee_index })
            }
        } else {
            if self.map.len() >= MAX_ATTESTATIONS_PER_SLOT {
                return Err(Error::ReachedMaxAttestationsPerSlot(
                    MAX_ATTESTATIONS_PER_SLOT,
                ));
            }

            self.map.insert(a.data.clone(), a.clone());
            Ok(InsertOutcome::NewAttestationData { committee_index })
        }
    }

    /// Returns an aggregated `Attestation` with the given `data`, if any.
    ///
    /// The given `a.data.slot` must match the slot that `self` was initialized with.
    pub fn get(&self, data: &AttestationData) -> Result<Option<Attestation<E>>, Error> {
        Ok(self.map.get(data).cloned())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// A pool of `Attestation` that is specially designed to store "unaggregated" attestations from
/// the native aggregation scheme.
///
/// **The `NaiveAggregationPool` does not do any signature or attestation verification. It assumes
/// that all `Attestation` objects provided are valid.**
///
/// ## Details
///
/// The pool sorts the `Attestation` by `attestation.data.slot`, then by `attestation.data`.
///
/// As each unaggregated attestation is added it is aggregated with any existing `attestation` with
/// the same `AttestationData`. Considering that the pool only accepts attestations with a single
/// signature, there should only ever be a single aggregated `Attestation` for any given
/// `AttestationData`.
///
/// The pool has a capacity for `SLOTS_RETAINED` slots, when a new `attestation.data.slot` is
/// provided, the oldest slot is dropped and replaced with the new slot. The pool can also be
/// pruned by supplying a `current_slot`; all existing attestations with a slot lower than
/// `current_slot - SLOTS_RETAINED` will be removed and any future attestation with a slot lower
/// than that will also be refused. Pruning is done automatically based upon the attestations it
/// receives and it can be triggered manually.
pub struct NaiveAggregationPool<E: EthSpec> {
    lowest_permissible_slot: RwLock<Slot>,
    maps: RwLock<HashMap<Slot, AggregatedAttestationMap<E>>>,
}

impl<E: EthSpec> Default for NaiveAggregationPool<E> {
    fn default() -> Self {
        Self {
            lowest_permissible_slot: RwLock::new(Slot::new(0)),
            maps: RwLock::new(HashMap::new()),
        }
    }
}

impl<E: EthSpec> NaiveAggregationPool<E> {
    /// Insert an attestation into `self`, aggregating it into the pool.
    ///
    /// The given attestation (`a`) must only have one signature and have an
    /// `attestation.data.slot` that is not lower than `self.lowest_permissible_slot`.
    ///
    /// The pool may be pruned if the given `attestation.data` has a slot higher than any
    /// previously seen.
    pub fn insert(&self, attestation: &Attestation<E>) -> Result<InsertOutcome, Error> {
        let slot = attestation.data.slot;
        let lowest_permissible_slot = *self.lowest_permissible_slot.read();

        // Reject any attestations that are too old.
        if slot < lowest_permissible_slot {
            return Err(Error::SlotTooLow {
                slot,
                lowest_permissible_slot,
            });
        }

        let mut maps = self.maps.write();

        let outcome = if let Some(map) = maps.get_mut(&slot) {
            map.insert(attestation)
        } else {
            // To avoid re-allocations, try and determine a rough initial capacity for the new item
            // by obtaining the mean size of all items in earlier epoch.
            let (count, sum) = maps
                .iter()
                // Only include epochs that are less than the given slot in the average. This should
                // generally avoid including recent epochs that are still "filling up".
                .filter(|(map_slot, _item)| **map_slot < slot)
                .map(|(_slot, map)| map.len())
                .fold((0, 0), |(count, sum), len| (count + 1, sum + len));

            // Use the mainnet default committee size if we can't determine an average.
            let initial_capacity = sum.checked_div(count).unwrap_or(128);

            let mut item = AggregatedAttestationMap::new(initial_capacity);
            let outcome = item.insert(attestation);
            maps.insert(slot, item);

            outcome
        };

        drop(maps);
        self.prune(slot);

        outcome
    }

    /// Returns an aggregated `Attestation` with the given `data`, if any.
    pub fn get(&self, data: &AttestationData) -> Result<Option<Attestation<E>>, Error> {
        self.maps
            .read()
            .iter()
            .find(|(slot, _map)| **slot == data.slot)
            .map(|(_slot, map)| map.get(data))
            .unwrap_or_else(|| Ok(None))
    }

    /// Removes any attestations with a slot lower than `current_slot` and bars any future
    /// attestations with a slot lower than `current_slot - SLOTS_RETAINED`.
    pub fn prune(&self, current_slot: Slot) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_slot = current_slot - Slot::from(SLOTS_RETAINED);
        *self.lowest_permissible_slot.write() = lowest_permissible_slot;
        let mut maps = self.maps.write();

        // Remove any maps that are definitely expired.
        maps.retain(|slot, _map| *slot >= lowest_permissible_slot);

        // If we have too many maps, remove the lowest amount to ensure we only have
        // `SLOTS_RETAINED` left.
        if maps.len() > SLOTS_RETAINED {
            let mut slots = maps.iter().map(|(slot, _map)| *slot).collect::<Vec<_>>();
            // Sort is generally pretty slow, however `SLOTS_RETAINED` is quite low so it should be
            // negligible.
            slots.sort_unstable();
            slots
                .into_iter()
                .take(maps.len().saturating_sub(SLOTS_RETAINED))
                .for_each(|slot| {
                    maps.remove(&slot);
                })
        }
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

    fn get_attestation(slot: Slot) -> Attestation<E> {
        let mut a: Attestation<E> = test_random_instance();
        a.data.slot = slot;
        a.aggregation_bits = BitList::with_capacity(4).expect("should create bitlist");
        a
    }

    fn sign(a: &mut Attestation<E>, i: usize, genesis_validators_root: Hash256) {
        a.sign(
            &generate_deterministic_keypair(i).sk,
            i,
            &Fork::default(),
            genesis_validators_root,
            &E::default_spec(),
        )
        .expect("should sign attestation");
    }

    fn unset_bit(a: &mut Attestation<E>, i: usize) {
        a.aggregation_bits
            .set(i, false)
            .expect("should unset aggregation bit")
    }

    #[test]
    fn single_attestation() {
        let mut a = get_attestation(Slot::new(0));

        let pool = NaiveAggregationPool::default();

        assert_eq!(
            pool.insert(&a),
            Err(Error::NoAggregationBitsSet),
            "should not accept attestation without any signatures"
        );

        sign(&mut a, 0, Hash256::random());

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

        sign(&mut a, 1, Hash256::random());

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

        let genesis_validators_root = Hash256::random();
        sign(&mut a_0, 0, genesis_validators_root);
        sign(&mut a_1, 1, genesis_validators_root);

        let pool = NaiveAggregationPool::default();

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
        sign(&mut a_different, 2, genesis_validators_root);
        assert_ne!(a_different.data.beacon_block_root, different_root);
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
        sign(&mut base, 0, Hash256::random());

        let pool = NaiveAggregationPool::default();

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
                    .map(|(slot, _map)| *slot)
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
        sign(&mut base, 0, Hash256::random());

        let pool = NaiveAggregationPool::default();

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
