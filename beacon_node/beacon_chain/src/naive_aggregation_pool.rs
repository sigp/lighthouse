use parking_lot::RwLock;
use std::collections::HashMap;
use types::{Attestation, AttestationData, EthSpec, Slot};

const SLOTS_RETAINED: usize = 3;

/// Returned upon successfully inserting an attestation into the pool.
#[derive(Debug)]
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

#[derive(Debug)]
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
    /// The given `attestation.aggregation_bits` field had a different length to the one currently
    /// stored. This indicates a fairly serious error somewhere in the code that called this
    /// function.
    InconsistentBitfieldLengths,
    /// The function to obtain a map index failed, this is an internal error.
    InvalidMapIndex(usize),
    /// The given `attestation` was for the incorrect slot. This is an internal error.
    IncorrectSlot { expected: Slot, attestation: Slot },
}

/// A collection of `Attestation` objects, keyed by their `attestation.data`. Enforces that all
/// `attestation` are from the same slot.
struct AggregatedAttestationMap<E: EthSpec> {
    map: HashMap<AttestationData, Attestation<E>>,
    slot: Slot,
}

impl<E: EthSpec> AggregatedAttestationMap<E> {
    /// Create an empty collection that will only contain attestation for the given `slot`.
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            map: <_>::default(),
        }
    }

    /// Insert an attestation into `self`, aggregating it into the pool.
    ///
    /// The given attestation (`a`) must only have one signature and be from the slot that `self`
    /// was initialized with.
    pub fn insert(&mut self, a: &Attestation<E>) -> Result<InsertOutcome, Error> {
        if a.data.slot != self.slot {
            return Err(Error::IncorrectSlot {
                expected: self.slot,
                attestation: a.data.slot,
            });
        }

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
            self.map.insert(a.data.clone(), a.clone());
            Ok(InsertOutcome::NewAttestationData { committee_index })
        }
    }

    /// Returns an aggregated `Attestation` with the given `data`, if any.
    ///
    /// The given `a.data.slot` must match the slot that `self` was initialized with.
    pub fn get(&self, data: &AttestationData) -> Result<Option<Attestation<E>>, Error> {
        if data.slot != self.slot {
            return Err(Error::IncorrectSlot {
                expected: self.slot,
                attestation: data.slot,
            });
        }

        Ok(self.map.get(data).cloned())
    }
}

/// A pool of `Attestation` that is specially designed to store "unaggregated" attestations from
/// the native aggregation scheme.
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
    maps: RwLock<Vec<AggregatedAttestationMap<E>>>,
}

impl<E: EthSpec> Default for NaiveAggregationPool<E> {
    fn default() -> Self {
        Self {
            lowest_permissible_slot: RwLock::new(Slot::new(0)),
            maps: RwLock::new(vec![]),
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
        let lowest_permissible_slot = *self.lowest_permissible_slot.read();

        // Reject any attestations that are too old.
        if attestation.data.slot < lowest_permissible_slot {
            return Err(Error::SlotTooLow {
                slot: attestation.data.slot,
                lowest_permissible_slot,
            });
        }

        // Prune the pool if this attestation indicates that the current slot has advanced.
        if (lowest_permissible_slot + SLOTS_RETAINED as u64) < attestation.data.slot + 1 {
            self.prune(attestation.data.slot)
        }

        let index = self.get_map_index(attestation.data.slot);

        self.maps
            .write()
            .get_mut(index)
            .ok_or_else(|| Error::InvalidMapIndex(index))?
            .insert(attestation)
    }

    /// Returns an aggregated `Attestation` with the given `data`, if any.
    ///
    /// The given `a.data.slot` must match the slot that `self` was initialized with.
    pub fn get(&self, data: &AttestationData) -> Result<Option<Attestation<E>>, Error> {
        self.maps
            .read()
            .iter()
            .find(|map| map.slot == data.slot)
            .map(|map| map.get(data))
            .unwrap_or_else(|| Ok(None))
    }

    /// Removes any attestations with a slot lower than `current_slot` and bars any future
    /// attestations with a slot lower than `current_slot - SLOTS_RETAINED`.
    pub fn prune(&self, current_slot: Slot) {
        // Taking advantage of saturating subtraction on `Slot`.
        let lowest_permissible_slot = current_slot - Slot::from(SLOTS_RETAINED);

        self.maps
            .write()
            .retain(|map| map.slot >= lowest_permissible_slot);

        *self.lowest_permissible_slot.write() = lowest_permissible_slot;
    }

    /// Returns the index of `self.maps` that matches `slot`.
    ///
    /// If there is no existing map for this slot one will be created. If `self.maps.len() >=
    /// SLOTS_RETAINED`, the map with the lowest slot will be replaced.
    fn get_map_index(&self, slot: Slot) -> usize {
        let mut maps = self.maps.write();

        if maps.len() < SLOTS_RETAINED || maps.is_empty() {
            let index = maps.len();
            maps.push(AggregatedAttestationMap::new(slot));
            return index;
        }

        if let Some(index) = maps.iter().position(|map| map.slot == slot) {
            return index;
        }

        let index = maps
            .iter()
            .enumerate()
            .min_by_key(|(_i, map)| map.slot)
            .map(|(i, _map)| i)
            .expect("maps cannot be empty due to previous .is_empty() check");

        maps[index] = AggregatedAttestationMap::new(slot);

        index
    }
}
