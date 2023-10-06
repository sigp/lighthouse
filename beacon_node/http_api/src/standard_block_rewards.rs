use crate::sync_committee_rewards::get_state_before_applying_block;
use crate::BlockId;
use crate::ExecutionOptimistic;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::lighthouse::StandardBlockReward;
use std::sync::Arc;
use warp_utils::reject::beacon_chain_error;
/// The difference between block_rewards and beacon_block_rewards is the later returns block
/// reward format that satisfies beacon-api specs
pub fn compute_beacon_block_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
) -> Result<(StandardBlockReward, ExecutionOptimistic, bool), warp::Rejection> {
    let (block, execution_optimistic, finalized) = block_id.blinded_block(&chain)?;

    let block_ref = block.message();

    let block_root = block.canonical_root();

    let mut state = get_state_before_applying_block(chain.clone(), &block)?;

    let rewards = chain
        .compute_beacon_block_reward(block_ref, block_root, &mut state)
        .map_err(beacon_chain_error)?;

    Ok((rewards, execution_optimistic, finalized))
}
