use crate::*;
use serde_derive::Serialize;
use std::collections::HashMap;

type ValidatorIndex = usize;

#[derive(Debug, PartialEq, Clone, Default, Serialize)]
pub struct PubkeyCache {
    map: HashMap<PublicKey, ValidatorIndex>,
}

impl PubkeyCache {
    /// Instantiates a new, empty cache.
    pub fn empty() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Returns the number of validator indices already in the map.
    pub fn len(&self) -> ValidatorIndex {
        self.map.len()
    }

    /// Inserts a validator index into the map.
    ///
    /// The added index must equal the number of validators already added to the map. This ensures
    /// that an index is never skipped.
    pub fn insert(&mut self, pubkey: PublicKey, index: ValidatorIndex) -> bool {
        if index == self.map.len() {
            self.map.insert(pubkey, index);
            true
        } else {
            false
        }
    }

    /// Inserts a validator index into the map.
    ///
    /// The added index must equal the number of validators already added to the map. This ensures
    /// that an index is never skipped.
    pub fn get(&self, pubkey: &PublicKey) -> Option<ValidatorIndex> {
        self.map.get(pubkey).cloned()
    }
}
