use crate::*;
use ssz::{Decode, Encode};

impl<T: EthSpec> StoreItem for PartialBeaconState<T> {
    fn db_column() -> DBColumn {
        DBColumn::BeaconState
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}
