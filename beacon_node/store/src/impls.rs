use crate::*;
use ssz::{Decode, Encode};

mod beacon_state;

impl StoreItem for BeaconBlock {
    fn db_column() -> DBColumn {
        DBColumn::BeaconBlock
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &mut [u8]) -> Result<Self, Error> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
