use crate::{
    beacon_fork_choice_store::{
        PersistedForkChoiceStoreV17, PersistedForkChoiceStoreV28, PersistedForkChoiceStoreV29,
    },
    metrics,
};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error, KeyValueStoreOp, StoreConfig, StoreItem};
use superstruct::superstruct;
use types::Hash256;

// If adding a new version you should update this type alias and fix the breakages.
pub type PersistedForkChoice = PersistedForkChoiceV29;

#[superstruct(
    variants(V17, V28, V29),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
pub struct PersistedForkChoice {
    #[superstruct(only(V17))]
    pub fork_choice_v17: fork_choice::PersistedForkChoiceV17,
    #[superstruct(only(V28, V29))]
    pub fork_choice: fork_choice::PersistedForkChoiceV28,
    #[superstruct(only(V17))]
    pub fork_choice_store_v17: PersistedForkChoiceStoreV17,
    #[superstruct(only(V28))]
    pub fork_choice_store_v28: PersistedForkChoiceStoreV28,
    #[superstruct(only(V29))]
    pub fork_choice_store: PersistedForkChoiceStoreV29,
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

impl PersistedForkChoiceV28 {
    // For the v28 to v29 schema migration
    pub fn from_bytes(bytes: &[u8], store_config: &StoreConfig) -> Result<Self, Error> {
        let decompressed_bytes = store_config
            .decompress_bytes(bytes)
            .map_err(Error::Compression)?;
        Self::from_ssz_bytes(&decompressed_bytes).map_err(Into::into)
    }

    // For the v29 to v28 schema migration
    pub fn as_bytes(&self, store_config: &StoreConfig) -> Result<Vec<u8>, Error> {
        store_config
            .compress_bytes(&self.as_ssz_bytes())
            .map_err(Error::Compression)
    }
}

// For the v28 to v29 schema migration
impl From<PersistedForkChoiceV28> for PersistedForkChoiceV29 {
    fn from(persisted_fork_choice_v28: PersistedForkChoiceV28) -> Self {
        Self {
            fork_choice: persisted_fork_choice_v28.fork_choice,
            fork_choice_store: persisted_fork_choice_v28.fork_choice_store_v28.into(),
        }
    }
}

// For the v29 to v28 schema migration
impl From<PersistedForkChoiceV29> for PersistedForkChoiceV28 {
    fn from(persisted_fork_choice_v29: PersistedForkChoiceV29) -> Self {
        Self {
            fork_choice: persisted_fork_choice_v29.fork_choice,
            fork_choice_store_v28: persisted_fork_choice_v29.fork_choice_store.into(),
        }
    }
}

impl PersistedForkChoiceV29 {
    pub fn from_bytes(bytes: &[u8], store_config: &StoreConfig) -> Result<Self, Error> {
        let decompressed_bytes = store_config
            .decompress_bytes(bytes)
            .map_err(Error::Compression)?;
        Self::from_ssz_bytes(&decompressed_bytes).map_err(Into::into)
    }

    pub fn as_bytes(&self, store_config: &StoreConfig) -> Result<Vec<u8>, Error> {
        let encode_timer = metrics::start_timer(&metrics::FORK_CHOICE_ENCODE_TIMES);
        let ssz_bytes = self.as_ssz_bytes();
        drop(encode_timer);

        let _compress_timer = metrics::start_timer(&metrics::FORK_CHOICE_COMPRESS_TIMES);
        store_config
            .compress_bytes(&ssz_bytes)
            .map_err(Error::Compression)
    }

    pub fn as_kv_store_op(
        &self,
        key: Hash256,
        store_config: &StoreConfig,
    ) -> Result<KeyValueStoreOp, Error> {
        Ok(KeyValueStoreOp::PutKeyValue(
            DBColumn::ForkChoice,
            key.as_slice().to_vec(),
            self.as_bytes(store_config)?,
        ))
    }
}
