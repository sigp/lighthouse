use block_producer::{DutiesReader, DutiesReaderError};
use std::collections::HashMap;
use std::sync::RwLock;
use types::{Epoch, Slot};

/// The information required for a validator to propose and attest during some epoch.
///
/// Generally obtained from a Beacon Node, this information contains the validators canonical index
/// (thier sequence in the global validator induction process) and the "shuffling" for that index
/// for some epoch.
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub struct EpochDuties {
    pub validator_index: u64,
    pub block_production_slot: Option<Slot>,
    // Future shard info
}

impl EpochDuties {
    /// Returns `true` if the supplied `slot` is a slot in which the validator should produce a
    /// block.
    pub fn is_block_production_slot(&self, slot: Slot) -> bool {
        match self.block_production_slot {
            Some(s) if s == slot => true,
            _ => false,
        }
    }
}

pub enum EpochDutiesMapError {
    Poisoned,
}

/// Maps an `epoch` to some `EpochDuties` for a single validator.
pub struct EpochDutiesMap {
    pub epoch_length: u64,
    pub map: RwLock<HashMap<Epoch, EpochDuties>>,
}

impl EpochDutiesMap {
    pub fn new(epoch_length: u64) -> Self {
        Self {
            epoch_length,
            map: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, epoch: Epoch) -> Result<Option<EpochDuties>, EpochDutiesMapError> {
        let map = self.map.read().map_err(|_| EpochDutiesMapError::Poisoned)?;
        match map.get(&epoch) {
            Some(duties) => Ok(Some(duties.clone())),
            None => Ok(None),
        }
    }

    pub fn insert(
        &self,
        epoch: Epoch,
        epoch_duties: EpochDuties,
    ) -> Result<Option<EpochDuties>, EpochDutiesMapError> {
        let mut map = self
            .map
            .write()
            .map_err(|_| EpochDutiesMapError::Poisoned)?;
        Ok(map.insert(epoch, epoch_duties))
    }
}

impl DutiesReader for EpochDutiesMap {
    fn is_block_production_slot(&self, slot: Slot) -> Result<bool, DutiesReaderError> {
        let epoch = slot.epoch(self.epoch_length);

        let map = self.map.read().map_err(|_| DutiesReaderError::Poisoned)?;
        let duties = map
            .get(&epoch)
            .ok_or_else(|| DutiesReaderError::UnknownEpoch)?;
        Ok(duties.is_block_production_slot(slot))
    }
}

// TODO: add tests.
