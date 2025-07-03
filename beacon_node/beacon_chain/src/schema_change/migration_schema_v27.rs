use crate::BeaconChainTypes;
use ssz::Encode;
use std::sync::Arc;
use store::metadata::DataColumnCustodyInfo;
use store::metadata::DATA_COLUMN_CUSTODY_INFO_KEY;
use store::{DBColumn, Error, HotColdDB, KeyValueStoreOp};
use tracing::info;

/// Add `DataColumnCustodyInfo` entry to v27.
pub fn upgrade_to_v27<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let ops = if db.spec.is_peer_das_scheduled() {
        info!("Adding `DataColumnCustodyInfo` to the db");
        let data_column_custody_info = DataColumnCustodyInfo {
            earliest_data_column_slot: None,
        };
        vec![KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconDataColumnCustodyInfo,
            DATA_COLUMN_CUSTODY_INFO_KEY.as_slice().to_vec(),
            data_column_custody_info.as_ssz_bytes(),
        )]
    } else {
        // Delete it from the db if PeerDAS hasn't been scheduled
        vec![KeyValueStoreOp::DeleteKey(
            DBColumn::BeaconDataColumnCustodyInfo,
            DATA_COLUMN_CUSTODY_INFO_KEY.as_slice().to_vec(),
        )]
    };

    Ok(ops)
}

pub fn downgrade_from_v27<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    if db.spec.is_peer_das_scheduled() {
        return Err(Error::MigrationError(
            "Cannot downgrade from v27 if peerDAS is scheduled".to_string(),
        ));
    }
    let ops = vec![KeyValueStoreOp::DeleteKey(
        DBColumn::BeaconDataColumnCustodyInfo,
        DATA_COLUMN_CUSTODY_INFO_KEY.as_slice().to_vec(),
    )];
    Ok(ops)
}
