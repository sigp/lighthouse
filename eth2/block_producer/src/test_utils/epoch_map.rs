use crate::{DutiesReader, DutiesReaderError};
use std::collections::HashMap;

pub type TestEpochMap = HashMap<u64, u64>;

impl DutiesReader for TestEpochMap {
    fn is_block_production_slot(&self, epoch: u64, slot: u64) -> Result<bool, DutiesReaderError> {
        match self.get(&epoch) {
            Some(s) if *s == slot => Ok(true),
            Some(s) if *s != slot => Ok(false),
            _ => Err(DutiesReaderError::UnknownEpoch),
        }
    }
}
