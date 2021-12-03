use crate::beacon_fork_choice_store::{PersistedForkChoiceStoreV1, PersistedForkChoiceStoreV7};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error, StoreItem};
use superstruct::superstruct;

// If adding a new version you should update this type alias and fix the breakages.
pub type PersistedForkChoice = PersistedForkChoiceV7;

#[superstruct(variants(V1, V7), variant_attributes(derive(Encode, Decode)), no_enum)]
pub struct PersistedForkChoice {
    pub fork_choice: fork_choice::PersistedForkChoice,
    #[superstruct(only(V1))]
    pub fork_choice_store: PersistedForkChoiceStoreV1,
    #[superstruct(only(V7))]
    pub fork_choice_store: PersistedForkChoiceStoreV7,
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

impl_store_item!(PersistedForkChoiceV1);
impl_store_item!(PersistedForkChoiceV7);
