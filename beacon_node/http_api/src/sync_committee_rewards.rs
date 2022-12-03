use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::{types::{ValidatorId}, Error};
use slog::{Logger};
use crate::BlockId;

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<SyncCommitteeRewards, Error> {

    // Get block_id with full_block()
        
    // Get state from chain
    
    // Call compute_sync_aggregate_reward
    
    // Stuff things into SyncCommitteeRewards

}