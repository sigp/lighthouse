use crate::{BeaconChainTypes, CheckPoint};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, StoreItem};
use types::BeaconState;

/// 32-byte key for accessing the `PersistedBeaconChain`.
pub const BEACON_CHAIN_DB_KEY: &str = "PERSISTEDBEACONCHAINPERSISTEDBEA";

#[derive(Encode, Decode)]
pub struct PersistedBeaconChain<T: BeaconChainTypes> {
    pub canonical_head: CheckPoint<T::EthSpec>,
    pub finalized_head: CheckPoint<T::EthSpec>,
    // TODO: operations pool.
    pub state: BeaconState<T::EthSpec>,
}

impl<T: BeaconChainTypes> StoreItem for PersistedBeaconChain<T> {
    fn db_column() -> DBColumn {
        DBColumn::BeaconChain
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &mut [u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
