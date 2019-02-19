use crate::{DutiesReader, DutiesReaderError};
use std::collections::HashMap;
use types::{Epoch, Slot};

pub struct EpochMap {
    epoch_length: u64,
    pub map: HashMap<Epoch, Slot>,
}

impl EpochMap {
    pub fn new(epoch_length: u64) -> Self {
        Self {
            epoch_length,
            map: HashMap::new(),
        }
    }
}

impl DutiesReader for EpochMap {
    fn is_block_production_slot(&self, slot: Slot) -> Result<bool, DutiesReaderError> {
        let epoch = slot.epoch(self.epoch_length);
        match self.map.get(&epoch) {
            Some(s) if *s == slot => Ok(true),
            Some(s) if *s != slot => Ok(false),
            _ => Err(DutiesReaderError::UnknownEpoch),
        }
    }
}
