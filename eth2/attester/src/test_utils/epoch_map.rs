use crate::{DutiesReader, DutiesReaderError};
use std::collections::HashMap;

pub struct TestEpochMap {
    epoch_length: u64,
    validator_index: Option<u64>,
    map: HashMap<u64, (u64, u64)>,
}

impl TestEpochMap {
    pub fn new(epoch_length: u64) -> Self {
        Self {
            epoch_length,
            validator_index: None,
            map: HashMap::new(),
        }
    }

    pub fn insert_attestation_shard(&mut self, slot: u64, shard: u64) {
        let epoch = slot / self.epoch_length;

        self.map.insert(epoch, (slot, shard));
    }

    pub fn set_validator_index(&mut self, index: Option<u64>) {
        self.validator_index = index;
    }
}

impl DutiesReader for TestEpochMap {
    fn attestation_shard(&self, slot: u64) -> Result<Option<u64>, DutiesReaderError> {
        let epoch = slot / self.epoch_length;

        match self.map.get(&epoch) {
            Some((attest_slot, attest_shard)) if *attest_slot == slot => Ok(Some(*attest_shard)),
            Some((attest_slot, _attest_shard)) if *attest_slot != slot => Ok(None),
            _ => Err(DutiesReaderError::UnknownEpoch),
        }
    }

    fn validator_index(&self) -> Option<u64> {
        self.validator_index
    }
}
