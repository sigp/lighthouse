use crate::head_tracker::SszHeadTracker;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, SimpleStoreItem};
use types::Hash256;

#[derive(Clone, Encode, Decode)]
pub struct PersistedBeaconChain {
    pub canonical_head_block_root: Hash256,
    pub genesis_block_root: Hash256,
    pub ssz_head_tracker: SszHeadTracker,
}

impl SimpleStoreItem for PersistedBeaconChain {
    fn db_column() -> DBColumn {
        DBColumn::BeaconChain
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
