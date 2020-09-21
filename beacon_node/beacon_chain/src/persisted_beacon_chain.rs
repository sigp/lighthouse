use crate::beacon_fork_choice_store::PersistedForkChoiceStore as ForkChoiceStore;
use crate::head_tracker::SszHeadTracker;
use fork_choice::PersistedForkChoice as ForkChoice;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, StoreItem};
use types::Hash256;

#[derive(Encode, Decode)]
pub struct PersistedBeaconChain {
    pub genesis_time: u64,
    pub genesis_block_root: Hash256,
    pub ssz_head_tracker: SszHeadTracker,
    pub persisted_fork_choice: PersistedForkChoice,
}

impl StoreItem for PersistedBeaconChain {
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

#[derive(Encode, Decode)]
pub struct PersistedForkChoice {
    pub fork_choice: ForkChoice,
    pub fork_choice_store: ForkChoiceStore,
}

impl StoreItem for PersistedForkChoice {
    fn db_column() -> DBColumn {
        DBColumn::ForkChoice
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> std::result::Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
