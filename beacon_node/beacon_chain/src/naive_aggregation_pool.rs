use parking_lot::RwLock;
use std::collections::HashMap;
use types::{Attestation, AttestationData, EthSpec, Slot};

const SLOTS_RETAINED: usize = 3;

#[derive(Debug)]
pub enum InsertOutcome {
    NewAttestationData { committee_index: usize },
    SignatureAlreadyKnown { committee_index: usize },
    SignatureAggregated { committee_index: usize },
}

#[derive(Debug)]
pub enum Error {
    IncorrectSlot { expected: Slot, attestation: Slot },
    NoAggregationBitsSet,
    MoreThanOneAggregationBitSet(usize),
    InconsistentBitfieldLengths,
    InvalidMapIndex(usize),
}

pub struct AggregatedAttestationMap<E: EthSpec> {
    map: HashMap<AttestationData, Attestation<E>>,
    slot: Slot,
}

impl<E: EthSpec> AggregatedAttestationMap<E> {
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            map: <_>::default(),
        }
    }

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

pub struct NaiveAggregationPool<E: EthSpec> {
    maps: RwLock<Vec<AggregatedAttestationMap<E>>>,
}

impl<E: EthSpec> Default for NaiveAggregationPool<E> {
    fn default() -> Self {
        Self {
            maps: RwLock::new(vec![]),
        }
    }
}

impl<E: EthSpec> NaiveAggregationPool<E> {
    pub fn insert(&self, attestation: &Attestation<E>) -> Result<InsertOutcome, Error> {
        let index = self.get_map_index(attestation.data.slot);

        self.maps
            .write()
            .get_mut(index)
            .ok_or_else(|| Error::InvalidMapIndex(index))?
            .insert(attestation)
    }

    pub fn get(&self, data: &AttestationData) -> Result<Option<Attestation<E>>, Error> {
        self.maps
            .read()
            .iter()
            .find(|map| map.slot == data.slot)
            .map(|map| map.get(data))
            .unwrap_or_else(|| Ok(None))
    }

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
