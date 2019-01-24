use crate::{BeaconChain, CheckPoint, ClientDB, SlotClock};
use std::collections::HashMap;
use std::sync::RwLockReadGuard;
use types::{BeaconBlock, BeaconState, Hash256};

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

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn insert_latest_attestation_target(&self, validator_index: u64, block_root: Hash256) {
        let mut targets = self
            .latest_attestation_targets
            .write()
            .expect("CRITICAL: CanonicalHead poisioned.");
        targets.insert(validator_index, block_root);
    }

    pub fn get_latest_attestation_target(&self, validator_index: u64) -> Option<Hash256> {
        let targets = self
            .latest_attestation_targets
            .read()
            .expect("CRITICAL: CanonicalHead poisioned.");

        match targets.get(validator_index) {
            Some(hash) => Some(hash.clone()),
            None => None,
        }
    }
}
