use crate::beacon_fork_choice_store::PersistedForkChoiceStoreV17;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error, StoreItem};
use superstruct::superstruct;

// If adding a new version you should update this type alias and fix the breakages.
pub type PersistedForkChoice = PersistedForkChoiceV17;

#[superstruct(variants(V17), variant_attributes(derive(Encode, Decode)), no_enum)]
pub struct PersistedForkChoice {
    pub fork_choice: fork_choice::PersistedForkChoice,
    pub fork_choice_store: PersistedForkChoiceStoreV17,
}

macro_rules! impl_store_item {
    ($type:ty) => {
        impl StoreItem for $type {
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
    };
}

impl_store_item!(PersistedForkChoiceV17);
