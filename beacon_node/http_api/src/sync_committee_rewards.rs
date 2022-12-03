use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::{types::ValidatorId, Error};
use eth2::lighthouse::SyncCommitteeAttestationRewards;
use slog::Logger;
use crate::BlockId;

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<SyncCommitteeAttestationRewards, Error> {

    // Get block_id with full_block()
    let block = chain
        .get_block(block_id)?
        .ok_or(Error::UnknownBlock(block_id))?
        .full_block()?;
        
    // Get state from chain
    let state = chain
        .get_state(&block.state_root(), Some(block.slot()))?
        .ok_or(Error::UnknownState(block.state_root()))?;

    // Convert a slot into the canonical block root from that slot: block_id.root(&chain).
    let block_root = block_id.root(&chain)?;
    
    // Call compute_sync_aggregate_reward
    let rewards = state.compute_sync_aggregate_reward(&block_root, &validators, &log)?;
    
    // Create SyncCommitteeRewards with calculated rewards
    Ok(SyncCommitteeAttestationRewards{
        execution_optimistic: false,
        finalized: false,
        data: Vec::new(),
    })
    
}
