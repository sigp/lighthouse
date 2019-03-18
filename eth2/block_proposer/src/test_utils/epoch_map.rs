use crate::{DutiesReader, DutiesReaderError};
use std::collections::HashMap;
use types::{Epoch, Fork, Slot};

pub struct EpochMap {
    slots_per_epoch: u64,
    pub map: HashMap<Epoch, Slot>,
}

impl EpochMap {
    pub fn new(slots_per_epoch: u64) -> Self {
        Self {
            slots_per_epoch,
            map: HashMap::new(),
        }
    }
}

impl DutiesReader for EpochMap {
    fn is_block_production_slot(&self, slot: Slot) -> Result<bool, DutiesReaderError> {
        let epoch = slot.epoch(self.slots_per_epoch);
        match self.map.get(&epoch) {
            Some(s) if *s == slot => Ok(true),
            Some(s) if *s != slot => Ok(false),
            _ => Err(DutiesReaderError::UnknownEpoch),
        }
    }

    fn fork(&self) -> Result<Fork, DutiesReaderError> {
        Ok(Fork {
            previous_version: [0; 4],
            current_version: [0; 4],
            epoch: Epoch::new(0),
        })
    }
}
