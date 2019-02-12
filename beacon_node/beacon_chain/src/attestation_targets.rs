use std::collections::HashMap;
use types::Hash256;

#[derive(Default)]
pub struct AttestationTargets {
    map: HashMap<u64, Hash256>,
}

impl AttestationTargets {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, validator_index: u64) -> Option<&Hash256> {
        self.map.get(&validator_index)
    }

    pub fn insert(&mut self, validator_index: u64, block_hash: Hash256) -> Option<Hash256> {
        self.map.insert(validator_index, block_hash)
    }
}
