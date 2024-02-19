use crate::beacon_fork_choice_store::{PersistedForkChoiceStoreV11, PersistedForkChoiceStoreV17};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error, StoreItem};
use superstruct::superstruct;

// If adding a new version you should update this type alias and fix the breakages.
pub type PersistedForkChoice = PersistedForkChoiceV20;

#[superstruct(
    variants(V11, V17, V20),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
pub struct PersistedForkChoice {
    #[superstruct(only(V11, V17))]
    pub fork_choice: fork_choice::PersistedForkChoiceV19,
    #[superstruct(only(V20))]
    pub fork_choice: fork_choice::PersistedForkChoiceV20,
    #[superstruct(only(V11))]
    pub fork_choice_store: PersistedForkChoiceStoreV11,
    #[superstruct(only(V17, V20))]
    pub fork_choice_store: PersistedForkChoiceStoreV17,
}

impl Into<PersistedForkChoiceV17> for PersistedForkChoiceV11 {
    fn into(self) -> PersistedForkChoiceV17 {
        PersistedForkChoiceV17 {
            fork_choice: self.fork_choice,
            fork_choice_store: self.fork_choice_store.into(),
        }
    }
}

impl Into<PersistedForkChoiceV11> for PersistedForkChoiceV17 {
    fn into(self) -> PersistedForkChoiceV11 {
        PersistedForkChoiceV11 {
            fork_choice: self.fork_choice,
            fork_choice_store: self.fork_choice_store.into(),
        }
    }
}

impl Into<PersistedForkChoiceV20> for PersistedForkChoiceV17 {
    fn into(self) -> PersistedForkChoiceV20 {
        PersistedForkChoiceV20 {
            fork_choice: self.fork_choice.into(),
            fork_choice_store: self.fork_choice_store,
        }
    }
}

impl Into<PersistedForkChoiceV17> for PersistedForkChoiceV20 {
    fn into(self) -> PersistedForkChoiceV17 {
        PersistedForkChoiceV17 {
            fork_choice: self.fork_choice.into(),
            fork_choice_store: self.fork_choice_store,
        }
    }
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

impl_store_item!(PersistedForkChoiceV11);
impl_store_item!(PersistedForkChoiceV17);
impl_store_item!(PersistedForkChoiceV20);
