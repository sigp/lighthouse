use crate::BeaconChainTypes;
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp};

use store::database::interface::BeaconNodeBackend;

pub fn upgrade_to_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // TODO(migration-v29) use db.is_redb() to check if its redb and then handle accordingly
    db.upgrade();
    Ok(vec![])
}

pub fn downgrade_from_v29<T: BeaconChainTypes>(
    _db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // TODO(migration-v29) use db.is_redb() to check if its redb and then handle accordingly
    // i.e. raise an error message in the redb case and dont allow a downgrade

    // For all other backends, just no-op
    Ok(vec![])
}
