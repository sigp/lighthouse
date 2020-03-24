use parking_lot::RwLock;
use std::collections::HashMap;
use types::{Attestation, AttestationData, EthSpec, Slot};

const SLOTS_RETAINED: usize = 3;

pub enum InsertOutcome {
    NewAttestationData,
    SignatureAlreadyKnown,
    SignatureAggregated,
}

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
            .collect::<Vec<_>>();

        let (committee_index, validator_index) = set_bits
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
                Ok(InsertOutcome::SignatureAlreadyKnown)
            } else {
                existing_attestation.aggregate(a);
                Ok(InsertOutcome::SignatureAggregated)
            }
        } else {
            self.map.insert(a.data.clone(), a.clone());
            Ok(InsertOutcome::NewAttestationData)
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

#[derive(Default)]
pub struct NaiveAggregationPool<E: EthSpec> {
    maps: Vec<RwLock<AggregatedAttestationMap<E>>>,
}

impl<E: EthSpec> NaiveAggregationPool<E> {
    pub fn insert(&mut self, attestation: &Attestation<E>) -> Result<InsertOutcome, Error> {
        let index = self.get_map_index(attestation.data.slot);

        self.maps
            .get(index)
            .ok_or_else(|| Error::InvalidMapIndex(index))?
            .write()
            .insert(attestation)
    }

    pub fn get(&self, data: &AttestationData) -> Result<Option<Attestation<E>>, Error> {
        self.maps
            .iter()
            .find(|map| map.read().slot == data.slot)
            .map(|map| map.read().get(data))
            .unwrap_or_else(|| Ok(None))
    }

    fn get_map_index(&mut self, slot: Slot) -> usize {
        if self.maps.len() < SLOTS_RETAINED || self.maps.is_empty() {
            let index = self.maps.len();
            self.maps
                .push(RwLock::new(AggregatedAttestationMap::new(slot)));
            return index;
        }

        if let Some(index) = self.maps.iter().position(|map| map.read().slot == slot) {
            return index;
        }

        let index = self
            .maps
            .iter()
            .enumerate()
            .min_by_key(|(_i, map)| map.read().slot)
            .map(|(i, _map)| i)
            .expect("maps cannot be empty due to previous .is_empty() check");

        self.maps[index] = RwLock::new(AggregatedAttestationMap::new(slot));

        index
    }
}
