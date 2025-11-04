use beacon_chain::store::metadata::CURRENT_SCHEMA_VERSION;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use serde::Serialize;
use std::sync::Arc;
use store::{AnchorInfo, BlobInfo, Split, StoreConfig};

#[derive(Debug, Serialize)]
pub struct DatabaseInfo {
    pub schema_version: u64,
    pub config: StoreConfig,
    pub split: Split,
    pub anchor: AnchorInfo,
    pub blob_info: BlobInfo,
}

pub fn info<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
) -> Result<DatabaseInfo, warp::Rejection> {
    let store = &chain.store;
    let split = store.get_split_info();
    let config = store.get_config().clone();
    let anchor = store.get_anchor_info();
    let blob_info = store.get_blob_info();

    Ok(DatabaseInfo {
        schema_version: CURRENT_SCHEMA_VERSION.as_u64(),
        config,
        split,
        anchor,
        blob_info,
    })
}
