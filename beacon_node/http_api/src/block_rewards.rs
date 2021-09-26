use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::lighthouse::{BlockReward, BlockRewardsQuery};
use state_processing::{
    per_block_processing, per_block_processing::BlockSignatureStrategy,
    state_advance::complete_state_advance,
};
use std::sync::Arc;
use warp_utils::reject::{
    beacon_chain_error, beacon_state_error, custom_bad_request, custom_server_error,
};

pub fn get_block_rewards<T: BeaconChainTypes>(
    query: BlockRewardsQuery,
    chain: Arc<BeaconChain<T>>,
) -> Result<Vec<BlockReward>, warp::Rejection> {
    let start_slot = query.start_slot;
    let end_slot = query.end_slot;
    let prior_slot = start_slot - 1;

    if start_slot > end_slot || start_slot == 0 {
        return Err(custom_bad_request(format!(
            "invalid start and end: {}, {}",
            start_slot, end_slot
        )));
    }

    let end_block_root = chain
        .block_root_at_slot(end_slot, WhenSlotSkipped::Prev)
        .map_err(beacon_chain_error)?
        .ok_or_else(|| custom_bad_request(format!("block at end slot {} unknown", end_slot)))?;

    let blocks = chain
        .store
        .load_blocks_to_replay(start_slot, end_slot, end_block_root)
        .map_err(|e| beacon_chain_error(e.into()))?;

    let state_root = chain
        .state_root_at_slot(prior_slot)
        .map_err(beacon_chain_error)?
        .ok_or_else(|| custom_bad_request(format!("prior state at slot {} unknown", prior_slot)))?;

    let mut state = chain
        .get_state(&state_root, Some(prior_slot))
        .and_then(|maybe_state| maybe_state.ok_or(BeaconChainError::MissingBeaconState(state_root)))
        .map_err(beacon_chain_error)?;

    state
        .build_all_caches(&chain.spec)
        .map_err(beacon_state_error)?;

    let mut block_rewards = Vec::with_capacity(blocks.len());

    for block in &blocks {
        // Advance to block slot.
        complete_state_advance(&mut state, None, block.slot(), &chain.spec).map_err(|e| {
            custom_server_error(format!(
                "state advance to slot {} failed: {:?}",
                block.slot(),
                e
            ))
        })?;

        // Compute block reward.
        let block_reward = chain
            .compute_block_reward(block.message(), block.canonical_root(), &state)
            .map_err(beacon_chain_error)?;
        block_rewards.push(block_reward);

        // Apply block.
        per_block_processing(
            &mut state,
            block,
            None,
            BlockSignatureStrategy::NoVerification,
            &chain.spec,
        )
        .map_err(|e| {
            custom_server_error(format!(
                "block processing failed at slot {}: {:?}",
                block.slot(),
                e
            ))
        })?;
    }

    Ok(block_rewards)
}
