use crate::BeaconChainTypes;
use std::sync::Arc;
use store::database::interface::BeaconNodeBackend;
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

    // Downgrade would probably be a no-op in all cases, and we just won't allow it (so we should maybe return an error always)

    // For all other backends, just no-op
    Ok(vec![])
}
