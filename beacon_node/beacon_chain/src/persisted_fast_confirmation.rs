use crate::beacon_chain::FAST_CONFIRMATION_DB_KEY;
use ssz::{Decode, Encode};
use store::{DBColumn, Error as StoreError, HotColdDB, ItemStore, KeyValueStoreOp, StoreItem};
use types::{EthSpec, Hash256};

/// The deepest root sent to the EL as the FCU safe block hash.
pub struct PersistedFastConfirmation(Hash256);

/// Spec: `get_root_confirmed_before_restart`. `None` if nothing was ever written.
pub fn load_root_confirmed_before_restart<E: EthSpec, Hot: ItemStore, Cold: ItemStore>(
    store: &HotColdDB<E, Hot, Cold>,
) -> Result<Option<Hash256>, StoreError> {
    Ok(store
        .get_item::<PersistedFastConfirmation>(&FAST_CONFIRMATION_DB_KEY)?
        .map(|persisted| persisted.0))
}

/// Write a confirmed root for the next restart to read.
pub fn persist_confirmed_root_in_batch(confirmed_root: Hash256) -> KeyValueStoreOp {
    PersistedFastConfirmation(confirmed_root).as_kv_store_op(FAST_CONFIRMATION_DB_KEY)
}

impl StoreItem for PersistedFastConfirmation {
    fn db_column() -> DBColumn {
        DBColumn::ForkChoice
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(PersistedFastConfirmation(Hash256::from_ssz_bytes(bytes)?))
    }
}
