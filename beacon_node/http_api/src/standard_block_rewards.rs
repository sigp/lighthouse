use crate::BlockId;
use crate::ExecutionOptimistic;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::StandardBlockReward;
use std::sync::Arc;
use warp_utils::reject::{beacon_chain_error, custom_not_found};
//// The difference between block_rewards and beacon_block_rewards is the later returns block
//// reward format that satisfies beacon-api specs
pub fn compute_beacon_block_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
) -> Result<(StandardBlockReward, ExecutionOptimistic), warp::Rejection> {
    let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

    let block_ref = block.message();

    let block_root = block.canonical_root();

    let slot = block.slot();

    let mut state = chain
        .get_state(&block.state_root(), Some(slot))
        .and_then(|maybe_state| {
            maybe_state.ok_or_else(|| BeaconChainError::MissingBeaconState(block.state_root()))
        })
        .map_err(|e| custom_not_found(format!("State is not available! {:?}", e)))?;

    let rewards = chain
        .compute_beacon_block_reward(block_ref, block_root, &mut state)
        .map_err(beacon_chain_error)?;

    Ok((rewards, execution_optimistic))
}
