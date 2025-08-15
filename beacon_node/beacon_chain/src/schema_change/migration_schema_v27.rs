use crate::BeaconChainTypes;
use std::sync::Arc;
use store::{Error, HotColdDB, metadata::SchemaVersion};

/// Add `DataColumnCustodyInfo` entry to v27.
pub fn upgrade_to_v27<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<(), Error> {
    if db.spec.is_peer_das_scheduled() {
        db.put_data_column_custody_info(None)?;
        db.store_schema_version_atomically(SchemaVersion(27), vec![])?;
    }

    Ok(())
}

pub fn downgrade_from_v27<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<(), Error> {
    if db.spec.is_peer_das_scheduled() {
        return Err(Error::MigrationError(
            "Cannot downgrade from v27 if peerDAS is scheduled".to_string(),
        ));
    }
    Ok(())
}
