use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::lighthouse::{BlockReward, BlockRewardsQuery};
use state_processing::BlockReplayer;
use std::sync::Arc;
use tracing::warn;
use warp_utils::reject::{beacon_state_error, custom_bad_request, unhandled_error};

/// Fetch block rewards for blocks from the canonical chain.
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
        .map_err(unhandled_error)?
        .ok_or_else(|| custom_bad_request(format!("block at end slot {} unknown", end_slot)))?;

    let blocks = chain
        .store
        .load_blocks_to_replay(start_slot, end_slot, end_block_root)
        .map_err(|e| unhandled_error(BeaconChainError::from(e)))?;

    let state_root = chain
        .state_root_at_slot(prior_slot)
        .map_err(unhandled_error)?
        .ok_or_else(|| custom_bad_request(format!("prior state at slot {} unknown", prior_slot)))?;

    // This branch is reached from the HTTP API. We assume the user wants
    // to cache states so that future calls are faster.
    let mut state = chain
        .get_state(&state_root, Some(prior_slot), true)
        .and_then(|maybe_state| maybe_state.ok_or(BeaconChainError::MissingBeaconState(state_root)))
        .map_err(unhandled_error)?;

    state
        .build_caches(&chain.spec)
        .map_err(beacon_state_error)?;

    let mut reward_cache = Default::default();
    let mut block_rewards = Vec::with_capacity(blocks.len());

    let block_replayer = BlockReplayer::new(state, &chain.spec)
        .pre_block_hook(Box::new(|state, block| {
            state.build_all_committee_caches(&chain.spec)?;

            // Compute block reward.
            let block_reward = chain.compute_block_reward(
                block.message(),
                block.canonical_root(),
                state,
                &mut reward_cache,
                query.include_attestations,
            )?;
            block_rewards.push(block_reward);
            Ok(())
        }))
        .state_root_iter(
            chain
                .forwards_iter_state_roots_until(prior_slot, end_slot)
                .map_err(unhandled_error)?,
        )
        .no_signature_verification()
        .minimal_block_root_verification()
        .apply_blocks(blocks, None)
        .map_err(unhandled_error)?;

    if block_replayer.state_root_miss() {
        warn!(%start_slot, %end_slot, "Block reward state root miss");
    }

    drop(block_replayer);

    Ok(block_rewards)
}
