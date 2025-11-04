use crate::{DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use types::{
    EthSpec, ExecutionPayload, ExecutionPayloadBellatrix, ExecutionPayloadCapella,
    ExecutionPayloadDeneb, ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionPayloadGloas,
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
impl_store_item!(ExecutionPayloadFulu);
impl_store_item!(ExecutionPayloadGloas);

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
        if let Ok(payload) = ExecutionPayloadGloas::from_ssz_bytes(bytes) {
            return Ok(Self::Gloas(payload));
        }

        if let Ok(payload) = ExecutionPayloadFulu::from_ssz_bytes(bytes) {
            return Ok(Self::Fulu(payload));
        }

        if let Ok(payload) = ExecutionPayloadElectra::from_ssz_bytes(bytes) {
            return Ok(Self::Electra(payload));
        }

        if let Ok(payload) = ExecutionPayloadDeneb::from_ssz_bytes(bytes) {
            return Ok(Self::Deneb(payload));
        }

        if let Ok(payload) = ExecutionPayloadCapella::from_ssz_bytes(bytes) {
            return Ok(Self::Capella(payload));
        }

        ExecutionPayloadBellatrix::from_ssz_bytes(bytes)
            .map(Self::Bellatrix)
            .map_err(Into::into)
    }
}
