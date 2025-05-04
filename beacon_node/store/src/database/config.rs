use crate::StoreError as Error;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::EthSpec;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct OnDiskStoreConfig {
    pub compact_on_prune: bool,
    pub compact_on_init: bool,
}

impl Default for OnDiskStoreConfig {
    fn default() -> Self {
        Self {
            compact_on_prune: true,
            compact_on_init: true,
        }
    }
}

impl OnDiskStoreConfig {
    pub fn new(compact_on_prune: bool, compact_on_init: bool) -> Self {
        Self {
            compact_on_prune,
            compact_on_init,
        }
    }
} 