use crate::*;
use ssz::{Decode, Encode};

pub mod beacon_state;
pub mod partial_beacon_state;

impl<T: EthSpec> SimpleStoreItem for BeaconBlock<T> {
    fn db_column() -> DBColumn {
        DBColumn::BeaconBlock
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
