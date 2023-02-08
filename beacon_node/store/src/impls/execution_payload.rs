use crate::{DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use types::{
    BlobsSidecar, EthSpec, ExecutionPayload, ExecutionPayloadCapella, ExecutionPayloadEip4844,
    ExecutionPayloadMerge,
};

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
impl_store_item!(ExecutionPayloadEip4844);
impl_store_item!(BlobsSidecar);

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
        ExecutionPayloadEip4844::from_ssz_bytes(bytes)
            .map(Self::Eip4844)
            .or_else(|_| {
                ExecutionPayloadCapella::from_ssz_bytes(bytes)
                    .map(Self::Capella)
                    .or_else(|_| ExecutionPayloadMerge::from_ssz_bytes(bytes).map(Self::Merge))
            })
            .map_err(Into::into)
    }
}
