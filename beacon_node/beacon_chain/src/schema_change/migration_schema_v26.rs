use crate::persisted_custody::{PersistedCustody, CUSTODY_DB_KEY};
use crate::validator_custody::CustodyContextSsz;
use crate::BeaconChainTypes;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use store::{DBColumn, Error, HotColdDB, KeyValueStoreOp, StoreItem};
use tracing::info;

#[derive(Debug, Encode, Decode, Clone)]
pub(crate) struct CustodyContextSszV1 {
    pub(crate) validator_custody_at_head: u64,
    pub(crate) persisted_is_supernode: bool,
}

pub(crate) struct PersistedCustodyV1(CustodyContextSszV1);

impl StoreItem for PersistedCustodyV1 {
    fn db_column() -> DBColumn {
        DBColumn::CustodyContext
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let custody_context = CustodyContextSszV1::from_ssz_bytes(bytes)?;
        Ok(PersistedCustodyV1(custody_context))
    }
}

/// Upgrade the `CustodyContext` entry to v26.
pub fn upgrade_to_v26<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let ops = if db.spec.is_peer_das_scheduled() {
        match db.get_item::<PersistedCustodyV1>(&CUSTODY_DB_KEY) {
            Ok(Some(PersistedCustodyV1(v1))) => {
                info!("Migrating `CustodyContext` to v26 schema");
                let custody_context_v2 = CustodyContextSsz {
                    validator_custody_at_head: v1.validator_custody_at_head,
                    persisted_is_supernode: v1.persisted_is_supernode,
                    epoch_validator_custody_requirements: vec![],
                };
                vec![KeyValueStoreOp::PutKeyValue(
                    DBColumn::CustodyContext,
                    CUSTODY_DB_KEY.as_slice().to_vec(),
                    PersistedCustody(custody_context_v2).as_store_bytes(),
                )]
            }
            _ => {
                vec![]
            }
        }
    } else {
        // Delete it from db if PeerDAS hasn't been scheduled
        vec![KeyValueStoreOp::DeleteKey(
            DBColumn::CustodyContext,
            CUSTODY_DB_KEY.as_slice().to_vec(),
        )]
    };

    Ok(ops)
}

pub fn downgrade_from_v26<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let res = db.get_item::<PersistedCustody>(&CUSTODY_DB_KEY);
    let ops = match res {
        Ok(Some(PersistedCustody(v2))) => {
            info!("Migrating `CustodyContext` back from v26 schema");
            let custody_context_v1 = CustodyContextSszV1 {
                validator_custody_at_head: v2.validator_custody_at_head,
                persisted_is_supernode: v2.persisted_is_supernode,
            };
            vec![KeyValueStoreOp::PutKeyValue(
                DBColumn::CustodyContext,
                CUSTODY_DB_KEY.as_slice().to_vec(),
                PersistedCustodyV1(custody_context_v1).as_store_bytes(),
            )]
        }
        _ => {
            // no op if it's not on the db, as previous versions gracefully handle data missing from disk.
            vec![]
        }
    };

    Ok(ops)
}
