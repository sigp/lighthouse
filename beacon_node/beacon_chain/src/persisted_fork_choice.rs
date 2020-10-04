use crate::beacon_fork_choice_store::PersistedForkChoiceStore as ForkChoiceStore;
use fork_choice::PersistedForkChoice as ForkChoice;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error, StoreItem};

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

    fn from_store_bytes(bytes: &[u8]) -> std::result::Result<Self, Error> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
