/* 
1. API handler `compute_sync_committe_rewards`
2. Load data using `chain` from `BeaconChain<T>`
 2.1 Load a block with `chain.get_blinded_block(block_root)`
 2.2 Load a state with `chain.get_state(state_root, None)`
 2.3 Convert a slot into the canonical block root from that slot: block_id.root(&chain)
3. Compute rewards by calling functions from `consensus/state_processing`
*/

// ---1---
// Copy the structure of an existing API handler, e.g. get_lighthouse_block_rewards.
pub fn get_sync_committee_rewards<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: BeaconState<T::EthSpec>,
    block: SignedBlindedBeaconBlock<T::EthSpec>,
) -> Result<SyncCommitteeRewards, Error> {

    let get_lighthouse_sync_committee_rewards = warp::path("lighthouse")
    .and(warp::path("analysis"))
    .and(warp::path("sync_committee_rewards"))
    .and(warp::query::<eth2::lighthouse::SyncCommitteeRewardsQuery>())
    .and(warp::path::end())
    .and(chain_filter.clone())
    .and(log_filter.clone())
    .and_then(|query, chain, log| {
        blocking_json_task(move || sync_committee_rewards::get_sync_committee_rewards(query, chain, log))
    });
}

// ---2---
// ---2.1---
// Load a block with chain.get_blinded_block(block_root).
pub fn get_blinded_block(
    &self,
    block_root: &Hash256,
) -> Result<Option<SignedBlindedBeaconBlock<T::EthSpec>>, Error> {
    Ok(self.store.get_blinded_block(block_root)?)
}

// ---2.2---
// Load a state with chain.get_state(state_root, None)
pub fn get_state(
    &self,
    state_root: &Hash256,
    slot: Option<Slot>,
) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
    Ok(self.store.get_state(state_root, slot)?)
}

// ---2.3---
// Convert a slot into the canonical block root from that slot: block_id.root(&chain).
/*
let canonical = chain
    .block_root_at_slot(block.slot(), WhenSlotSkipped::None)
    .map_err(warp_utils::reject::beacon_chain_error)?
    .map_or(false, |canonical| root == canonical);
*/

// ---3---
// Once we have the block(s) and state that we need, we can compute the rewards using snippets of logic extracted from consensus/state_processing.
// Call this function
pub fn compute_sync_committee_rewards<T: EthSpec>(
    state: &BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(u64, u64), BlockProcessingError> {
    let total_active_balance = state.get_total_active_balance()?;
    let total_active_increments =
        total_active_balance.safe_div(spec.effective_balance_increment)?;
    let total_base_rewards = BaseRewardPerIncrement::new(total_active_balance, spec)?
        .as_u64()
        .safe_mul(total_active_increments)?;
    let max_participant_rewards = total_base_rewards
        .safe_mul(SYNC_REWARD_WEIGHT)?
        .safe_div(WEIGHT_DENOMINATOR)?
        .safe_div(T::slots_per_epoch())?;
    let participant_reward = max_participant_rewards.safe_div(T::SyncCommitteeSize::to_u64())?;
    let proposer_reward = participant_reward
        .safe_mul(PROPOSER_WEIGHT)?
        .safe_div(WEIGHT_DENOMINATOR.safe_sub(PROPOSER_WEIGHT)?)?;
    Ok((participant_reward, proposer_reward))
}