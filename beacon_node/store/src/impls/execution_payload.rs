use crate::{DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use types::{EthSpec, ExecutionPayload, ExecutionPayloadCapella, ExecutionPayloadMerge};

macro_rules! impl_store_item {
    ($ty_name:ident) => {
        impl<E: EthSpec> StoreItem for $ty_name<E> {
            fn db_column() -> DBColumn {
                DBColumn::ExecPayload
            }

            fn as_store_bytes(&self) -> Vec<u8> {
                self.as_ssz_bytes()
            }

            fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(Self::from_ssz_bytes(bytes)?)
            }
        }
    };
}
impl_store_item!(ExecutionPayloadMerge);
impl_store_item!(ExecutionPayloadCapella);

/// This fork-agnostic implementation should be only used for writing.
///
/// It is very inefficient at reading, and decoding the desired fork-specific variant is recommended
/// instead.
impl<E: EthSpec> StoreItem for ExecutionPayload<E> {
    fn db_column() -> DBColumn {
        DBColumn::ExecPayload
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ExecutionPayloadCapella::from_ssz_bytes(bytes)
            .map(Self::Capella)
            .or_else(|_| ExecutionPayloadMerge::from_ssz_bytes(bytes).map(Self::Merge))
            .map_err(Into::into)
    }
}
