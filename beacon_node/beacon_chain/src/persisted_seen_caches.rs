use crate::observed_attestations::SszObservedAttestations;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error, StoreItem};

#[derive(Encode, Decode)]
pub struct PersistedSeenCaches {
    pub observed_attestations: SszObservedAttestations,
}

impl StoreItem for PersistedSeenCaches {
    fn db_column() -> DBColumn {
        DBColumn::SeenCaches
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> std::result::Result<Self, Error> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
