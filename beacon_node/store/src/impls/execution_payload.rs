use crate::{DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use types::{EthSpec, ExecutionPayload};

impl<E: EthSpec> StoreItem for ExecutionPayload<E> {
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
