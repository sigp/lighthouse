use crate::custody_context::CustodyContextSsz;
use ssz::{Decode, Encode};
use std::sync::Arc;
use store::{DBColumn, Error as StoreError, HotColdDB, ItemStore, StoreItem};
use types::{EthSpec, Hash256};

/// 32-byte key for accessing the `CustodyContext`. All zero because `CustodyContext` has its own column.
pub const CUSTODY_DB_KEY: Hash256 = Hash256::ZERO;

pub struct PersistedCustody(pub CustodyContextSsz);

pub fn load_custody_context<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
) -> Option<CustodyContextSsz> {
    let res: Result<Option<PersistedCustody>, _> =
        store.get_item::<PersistedCustody>(&CUSTODY_DB_KEY);
    // Load context from the store
    match res {
        Ok(Some(c)) => Some(c.0),
        _ => None,
    }
}

/// Attempt to persist the custody context object to `self.store`.
pub fn persist_custody_context<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
    custody_context: CustodyContextSsz,
) -> Result<(), store::Error> {
    store.put_item(&CUSTODY_DB_KEY, &PersistedCustody(custody_context))
}

impl StoreItem for PersistedCustody {
    fn db_column() -> DBColumn {
        DBColumn::CustodyContext
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let custody_context = CustodyContextSsz::from_ssz_bytes(bytes)?;

        Ok(PersistedCustody(custody_context))
    }
}
