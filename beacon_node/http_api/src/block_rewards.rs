use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::lighthouse::{BlockReward, BlockRewardsQuery};
use lru::LruCache;
use slog::{debug, warn, Logger};
use state_processing::BlockReplayer;
use std::sync::Arc;
use types::BeaconBlock;
use warp_utils::reject::{
    beacon_chain_error, beacon_state_error, custom_bad_request, custom_server_error,
};

const STATE_CACHE_SIZE: usize = 2;

/// Fetch block rewards for blocks from the canonical chain.
pub fn get_block_rewards<T: BeaconChainTypes>(
    query: BlockRewardsQuery,
    chain: Arc<BeaconChain<T>>,
    log: Logger,
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
                .map_err(beacon_chain_error)?,
        )
        .no_signature_verification()
        .minimal_block_root_verification()
        .apply_blocks(blocks, None)
        .map_err(beacon_chain_error)?;

    if block_replayer.state_root_miss() {
        warn!(
            log,
            "Block reward state root miss";
            "start_slot" => start_slot,
            "end_slot" => end_slot,
        );
    }

    drop(block_replayer);

    Ok(block_rewards)
}

/// Compute block rewards for blocks passed in as input.
pub fn compute_block_rewards<T: BeaconChainTypes>(
    blocks: Vec<BeaconBlock<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    log: Logger,
) -> Result<Vec<BlockReward>, warp::Rejection> {
    let mut block_rewards = Vec::with_capacity(blocks.len());
    let mut state_cache = LruCache::new(STATE_CACHE_SIZE);
    let mut reward_cache = Default::default();

    for block in blocks {
        let parent_root = block.parent_root();

        // Check LRU cache for a constructed state from a previous iteration.
        let state = if let Some(state) = state_cache.get(&(parent_root, block.slot())) {
            debug!(
                log,
                "Re-using cached state for block rewards";
                "parent_root" => ?parent_root,
                "slot" => block.slot(),
            );
            state
        } else {
            debug!(
                log,
                "Fetching state for block rewards";
                "parent_root" => ?parent_root,
                "slot" => block.slot()
            );
            let parent_block = chain
                .get_blinded_block(&parent_root)
                .map_err(beacon_chain_error)?
                .ok_or_else(|| {
                    custom_bad_request(format!(
                        "parent block not known or not canonical: {:?}",
                        parent_root
                    ))
                })?;

            let parent_state = chain
                .get_state(&parent_block.state_root(), Some(parent_block.slot()))
                .map_err(beacon_chain_error)?
                .ok_or_else(|| {
                    custom_bad_request(format!(
                        "no state known for parent block: {:?}",
                        parent_root
                    ))
                })?;

            let block_replayer = BlockReplayer::new(parent_state, &chain.spec)
                .no_signature_verification()
                .state_root_iter([Ok((parent_block.state_root(), parent_block.slot()))].into_iter())
                .minimal_block_root_verification()
                .apply_blocks(vec![], Some(block.slot()))
                .map_err(beacon_chain_error)?;

            if block_replayer.state_root_miss() {
                warn!(
                    log,
                    "Block reward state root miss";
                    "parent_slot" => parent_block.slot(),
                    "slot" => block.slot(),
                );
            }

            let mut state = block_replayer.into_state();
            state
                .build_all_committee_caches(&chain.spec)
                .map_err(beacon_state_error)?;

            state_cache
                .get_or_insert((parent_root, block.slot()), || state)
                .ok_or_else(|| {
                    custom_server_error("LRU cache insert should always succeed".into())
                })?
        };

        // Compute block reward.
        let block_reward = chain
            .compute_block_reward(
                block.to_ref(),
                block.canonical_root(),
                state,
                &mut reward_cache,
                true,
            )
            .map_err(beacon_chain_error)?;
        block_rewards.push(block_reward);
    }

    Ok(block_rewards)
}
