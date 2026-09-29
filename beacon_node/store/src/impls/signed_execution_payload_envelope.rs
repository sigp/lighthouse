use ssz::{Decode, Encode};
use types::{EthSpec, SignedExecutionPayloadEnvelopeSummary};

use crate::{DBColumn, Error, StoreItem};

impl<E: EthSpec> StoreItem for SignedExecutionPayloadEnvelopeSummary<E> {
    fn db_column() -> DBColumn {
        DBColumn::PayloadSummary
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}
