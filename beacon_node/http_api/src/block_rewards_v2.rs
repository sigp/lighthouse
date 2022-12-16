use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::BlockRewardsV2;
use slog::Logger;
use crate::BlockId;

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<BlockRewardsV2, warp::Rejection> {

    Ok(BlockRewardsV2{
        execution_optimistic: false,
        finalized: false,
        data: vec![],
    })

}