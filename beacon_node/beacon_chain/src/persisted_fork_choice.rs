use crate::beacon_fork_choice_store::{PersistedForkChoiceStoreV17, PersistedForkChoiceStoreV28};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io::{Read, Write};
use store::{DBColumn, Error, KeyValueStoreOp, StoreConfig, StoreItem};
use superstruct::superstruct;
use types::Hash256;
use zstd::{Decoder, Encoder};

// If adding a new version you should update this type alias and fix the breakages.
pub type PersistedForkChoice = PersistedForkChoiceV28;

#[superstruct(
    variants(V17, V28),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
pub struct PersistedForkChoice {
    pub fork_choice: fork_choice::PersistedForkChoice,
    #[superstruct(only(V17))]
    pub fork_choice_store_v17: PersistedForkChoiceStoreV17,
    #[superstruct(only(V28))]
    pub fork_choice_store: PersistedForkChoiceStoreV28,
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
    pub fn from_bytes(bytes: &[u8], store_config: &StoreConfig) -> Result<Self, Error> {
        Self::from_ssz_bytes(&uncompress_bytes(bytes, store_config)?).map_err(Into::into)
    }

    pub fn as_bytes(&self, store_config: &StoreConfig) -> Result<Vec<u8>, Error> {
        compress_bytes(&self.as_ssz_bytes(), store_config)
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

// FIXME(sproul): dedupe?
fn compress_bytes(input: &[u8], config: &StoreConfig) -> Result<Vec<u8>, Error> {
    let compression_level = config.compression_level;
    let mut out = Vec::with_capacity(config.estimate_compressed_size(input.len()));
    let mut encoder = Encoder::new(&mut out, compression_level).map_err(Error::Compression)?;
    encoder.write_all(input).map_err(Error::Compression)?;
    encoder.finish().map_err(Error::Compression)?;
    Ok(out)
}

fn uncompress_bytes(input: &[u8], config: &StoreConfig) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(config.estimate_decompressed_size(input.len()));
    let mut decoder = Decoder::new(input).map_err(Error::Compression)?;
    decoder.read_to_end(&mut out).map_err(Error::Compression)?;
    Ok(out)
}
