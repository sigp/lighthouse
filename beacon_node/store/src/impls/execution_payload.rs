use crate::{DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use types::{
    BlobSidecarList, EthSpec, ExecutionPayload, ExecutionPayloadBellatrix, ExecutionPayloadCapella,
    ExecutionPayloadDeneb, ExecutionPayloadElectra,
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
impl_store_item!(ExecutionPayloadBellatrix);
impl_store_item!(ExecutionPayloadCapella);
impl_store_item!(ExecutionPayloadDeneb);
impl_store_item!(ExecutionPayloadElectra);
impl_store_item!(BlobSidecarList);

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
        ExecutionPayloadElectra::from_ssz_bytes(bytes)
            .map(Self::Electra)
            .or_else(|_| {
                ExecutionPayloadDeneb::from_ssz_bytes(bytes)
                    .map(Self::Deneb)
                    .or_else(|_| {
                        ExecutionPayloadCapella::from_ssz_bytes(bytes)
                            .map(Self::Capella)
                            .or_else(|_| {
                                ExecutionPayloadBellatrix::from_ssz_bytes(bytes)
                                    .map(Self::Bellatrix)
                            })
                    })
            })
            .map_err(Into::into)
    }
}
