use crate::{BeaconChainTypes, CheckPoint};
use operation_pool::PersistedOperationPool;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, StoreItem};
use types::Hash256;

/// 32-byte key for accessing the `PersistedBeaconChain`.
pub const BEACON_CHAIN_DB_KEY: &str = "PERSISTEDBEACONCHAINPERSISTEDBEA";

#[derive(Encode, Decode)]
pub struct PersistedBeaconChain<T: BeaconChainTypes> {
    pub canonical_head: CheckPoint<T::EthSpec>,
    pub op_pool: PersistedOperationPool<T::EthSpec>,
    pub genesis_block_root: Hash256,
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
