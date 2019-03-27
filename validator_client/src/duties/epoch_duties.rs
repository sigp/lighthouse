use block_proposer::{DutiesReader, DutiesReaderError};
use std::collections::HashMap;
use std::sync::RwLock;
use types::{Epoch, Fork, PublicKey, Slot};

/// The information required for a validator to propose and attest during some epoch.
///
/// Generally obtained from a Beacon Node, this information contains the validators canonical index
/// (their sequence in the global validator induction process) and the "shuffling" for that index
/// for some epoch.
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub struct EpochDuty {
    pub block_production_slot: Option<Slot>,
    pub committee_slot: Slot,
    pub committee_shard: u64,
    pub committee_index: u64,
}

impl EpochDuty {
    /// Returns `true` if work needs to be done in the supplied `slot`
    pub fn is_work_slot(&self, slot: Slot) -> bool {
        // if validator is required to produce a slot return true
        match self.block_production_slot {
            Some(s) if s == slot => return true,
            _ => false,
        }

        if self.committee_slot == slot {
            return true;
        }
        return false;
    }
}
/// Maps a list of public keys (many validators) to an EpochDuty.
pub struct EpochDuties {
    inner: HashMap<PublicKey, Option<EpochDuty>>,
}

pub enum EpochDutiesMapError {
    Poisoned,
}

/// Maps an `epoch` to some `EpochDuties` for a single validator.
pub struct EpochDutiesMap {
    pub slots_per_epoch: u64,
    pub map: RwLock<HashMap<Epoch, EpochDuties>>,
}

impl EpochDutiesMap {
    pub fn new(slots_per_epoch: u64) -> Self {
        Self {
            slots_per_epoch,
            map: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, epoch: Epoch) -> Result<Option<EpochDuties>, EpochDutiesMapError> {
        let map = self.map.read().map_err(|_| EpochDutiesMapError::Poisoned)?;
        match map.get(&epoch) {
            Some(duties) => Ok(Some(*duties)),
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
        let epoch = slot.epoch(self.slots_per_epoch);

        let map = self.map.read().map_err(|_| DutiesReaderError::Poisoned)?;
        let duties = map
            .get(&epoch)
            .ok_or_else(|| DutiesReaderError::UnknownEpoch)?;
        Ok(duties.is_block_production_slot(slot))
    }

    fn fork(&self) -> Result<Fork, DutiesReaderError> {
        // TODO: this is garbage data.
        //
        // It will almost certainly cause signatures to fail verification.
        Ok(Fork {
            previous_version: [0; 4],
            current_version: [0; 4],
            epoch: Epoch::new(0),
        })
    }
}

// TODO: add tests.
