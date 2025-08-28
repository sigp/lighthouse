use crate::BeaconChainTypes;
use std::sync::Arc;
use store::{metadata::SchemaVersion, Error, HotColdDB, KeyValueStoreOp};

#[cfg(feature = "redb")]
use store::config::BeaconNodeBackend;
// Result<Vec<KeyValueStoreOp>, Error>
pub fn upgrade_to_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>
) -> Result<Vec<KeyValueStoreOp>, Error> {
    #[cfg(feature = "redb")]
    {
        if let Some(backend) = db.backend() {
            use store::database::interface::BeaconNodeBackend;

            if let BeaconNodeBackend::Redb(redb) = backend {
                match redb.upgrade() {
                    Ok(did_upgrade) => {
                        if did_upgrade {
                            info!("Redb file format successfully upgraded to v29");
                        } else {
                            use tracing::info;

                            info!("Redb file-format already at v29, no upgrade needed");
                        }
                    }
                    Err(e) => {
                        return Err(Error::MigrationError(format!{
                            "Redb file-format upgrade failed: {e}"
                        }));
                    }
                }
            }
        }
    }
    
    Ok(vec![])
}

pub fn downgrade_from_v29<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    #[cfg(feature = "redb")]
    {
        if let Some(backend) = db.backend() {
            use store::database::interface::BeaconNodeBackend;

            if let BeaconNodeBackend::Redb(_) = backend {
                return Err(Error::MigrationError(
                    "Cannot downgrade from v29: Redb file format upgrade is irreversible".to_string()
                ));
            }
        }
    }
    
    // For all other backends, just no-op
    Ok(vec![])
}


