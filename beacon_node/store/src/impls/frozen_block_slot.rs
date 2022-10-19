use crate::{DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use types::Slot;

pub struct FrozenBlockSlot(pub Slot);

impl StoreItem for FrozenBlockSlot {
    fn db_column() -> DBColumn {
        DBColumn::BeaconBlock
    }

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.as_ssz_bytes())
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(FrozenBlockSlot(Slot::from_ssz_bytes(bytes)?))
    }
}
