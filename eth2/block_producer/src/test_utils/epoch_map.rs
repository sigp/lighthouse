use crate::{DutiesReader, DutiesReaderError};
use std::collections::HashMap;

pub struct TestEpochMap {
    epoch_length: u64,
    pub map: HashMap<u64, u64>,
}

impl TestEpochMap {
    pub fn new(epoch_length: u64) -> Self {
        Self {
            epoch_length,
            map: HashMap::new(),
        }
    }
}

impl DutiesReader for TestEpochMap {
    fn is_block_production_slot(&self, slot: u64) -> Result<bool, DutiesReaderError> {
        let epoch = slot / self.epoch_length;
        match self.map.get(&epoch) {
            Some(s) if *s == slot => Ok(true),
            Some(s) if *s != slot => Ok(false),
            _ => Err(DutiesReaderError::UnknownEpoch),
        }
    }
}
