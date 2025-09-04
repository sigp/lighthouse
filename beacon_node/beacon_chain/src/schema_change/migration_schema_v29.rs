use crate::BeaconChainTypes;
use std::sync::Arc;
use store::database::interface::BeaconNodeBackend;
use store::{Error, HotColdDB, KeyValueStoreOp};

pub fn upgrade_to_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    db.upgrade();
    Ok(vec![])
}

pub fn downgrade_from_v29<T: BeaconChainTypes>(
    _db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    #[cfg(feature = "redb")]
    {
        if let Some(backend) = db.backend() {
            if let BeaconNodeBackend::Redb(_) = backend {
                return Err(Error::MigrationError(
                    "Cannot downgrade from v29: Redb file format upgrade is irreversible"
                        .to_string(),
                ));
            }
        }
    }

    // Downgrade would probably be a no-op in all cases, and we just won't allow it (so we should maybe return an error always)

    // For all other backends, just no-op
    Ok(vec![])
}
