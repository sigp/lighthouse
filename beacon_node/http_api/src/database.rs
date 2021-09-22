use beacon_chain::store::{metadata::CURRENT_SCHEMA_VERSION, AnchorInfo};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::lighthouse::DatabaseInfo;
use std::sync::Arc;
use types::SignedBeaconBlock;

pub fn info<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
) -> Result<DatabaseInfo, warp::Rejection> {
    let store = &chain.store;
    let split = store.get_split_info();
    let anchor = store.get_anchor_info();

    Ok(DatabaseInfo {
        schema_version: CURRENT_SCHEMA_VERSION.as_u64(),
        split,
        anchor,
    })
}

pub fn historical_blocks<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
) -> Result<AnchorInfo, warp::Rejection> {
    chain
        .import_historical_block_batch(&blocks)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let anchor = chain.store.get_anchor_info().ok_or_else(|| {
        warp_utils::reject::custom_bad_request("node is not checkpoint synced".to_string())
    })?;
    Ok(anchor)
}
