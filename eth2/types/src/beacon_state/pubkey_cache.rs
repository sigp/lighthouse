use crate::*;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

type ValidatorIndex = usize;

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct PubkeyCache {
    /// Maintain the number of keys added to the map. It is not sufficient to just use the HashMap
    /// len, as it does not increase when duplicate keys are added. Duplicate keys are used during
    /// testing.
    len: usize,
    map: HashMap<PublicKey, ValidatorIndex>,
}

impl PubkeyCache {
    /// Returns the number of validator indices added to the map so far.
    pub fn len(&self) -> ValidatorIndex {
        self.len
    }

    /// Inserts a validator index into the map.
    ///
    /// The added index must equal the number of validators already added to the map. This ensures
    /// that an index is never skipped.
    pub fn insert(&mut self, pubkey: PublicKey, index: ValidatorIndex) -> bool {
        if index == self.len {
            self.map.insert(pubkey, index);
            self.len += 1;
            true
        } else {
            false
        }
    }

    /// Looks up a validator index's by their public key.
    pub fn get(&self, pubkey: &PublicKey) -> Option<ValidatorIndex> {
        self.map.get(pubkey).copied()
    }
}
