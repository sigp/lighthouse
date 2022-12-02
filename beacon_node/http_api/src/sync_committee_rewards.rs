/* 
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{BlockId, ValidatorId};
use slog::{Logger};

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<SyncCommitteeRewards, Error> {

    - Get block from block_id
    - Get state from chain
    - Call compute_sync_aggregate_reward
    - Stuff things into SyncCommitteeRewards

}

*/