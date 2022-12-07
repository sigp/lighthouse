use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::BlockRewardsV2;
use slog::Logger;
use crate::BlockId;

pub fn compute_block_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<BlockRewardsV2, Error> {

    // Create AttestationRewards with calculated rewards
    Ok(BlockRewardsV2{
        execution_optimistic: false,
        finalized: false,
        data: Vec::new(),
    })

}