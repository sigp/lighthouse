use crate::beacon_chain::FAST_CONFIRMATION_DB_KEY;
use crate::canonical_head::FastConfirmationRoots;
use ssz::{Decode, Encode};
use store::{DBColumn, Error as StoreError, HotColdDB, ItemStore, KeyValueStoreOp, StoreItem};
use types::EthSpec;

pub fn load_fast_confirmation_roots<E: EthSpec, Hot: ItemStore, Cold: ItemStore>(
    store: &HotColdDB<E, Hot, Cold>,
) -> Result<Option<FastConfirmationRoots>, StoreError> {
    store.get_item::<FastConfirmationRoots>(&FAST_CONFIRMATION_DB_KEY)
}

pub fn persist_fast_confirmation_roots_in_batch(roots: &FastConfirmationRoots) -> KeyValueStoreOp {
    roots.as_kv_store_op(FAST_CONFIRMATION_DB_KEY)
}

impl StoreItem for FastConfirmationRoots {
    fn db_column() -> DBColumn {
        DBColumn::ForkChoice
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}
