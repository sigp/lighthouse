use crate::BeaconChainTypes;
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp};

pub fn upgrade_to_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    db.upgrade()?;
    Ok(vec![])
}

pub fn downgrade_from_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    if db.is_redb() {
        return Err(Error::MigrationError(
            "Downgrade from v29 not supported for Redb".into(),
        ));
    }
    Ok(vec![])
}
