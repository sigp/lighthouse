use crate::BlockId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::lighthouse::BlockRewardsV2;
use slog::Logger;
use std::sync::Arc;

//// The difference between block_rewards and beacon_block_rewards is the later returns block
//// reward format that satisfies beacon-api specs
pub fn compute_beacon_block_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    log: Logger,
) -> Result<BlockRewardsV2, warp::Rejection> {
    let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

    let spec = &chain.spec;
    let block_body = block.message().body();

    let proposer_reward = 0;
    let sync_aggregate_reward = 0;
    let proposer_slashing_reward = 0;
    let attester_slashing_reward = 0;

    if let Ok(_) = block_body.sync_aggregate() {}

    Ok(BlockRewardsV2 {
        execution_optimistic: false,
        finalized: false,
        data: vec![],
    })
}
