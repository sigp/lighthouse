use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::SyncCommitteeAttestationRewards;
use slog::Logger;
use state_processing::{per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards};
use crate::BlockId;

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<SyncCommitteeAttestationRewards, E> {

    let spec = chain.spec;

    let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

    let slot = block.slot();

    let state_root = block.state_root();

    // Technically we should use the pre-block state, but it won't matter because
    // compute_sync_aggregate_rewards() only uses state.get_total_active_balance() which only changes on epoch boundaries.
    // So, the "wrong" state will still give the same result.
    let state = chain.get_state(&state_root, Some(slot))?.unwrap();

    let (_, rewards) = compute_sync_aggregate_rewards(&state, &spec)?;
    
    // Create SyncCommitteeRewards with calculated rewards
    Ok(SyncCommitteeAttestationRewards{
        execution_optimistic: false,
        finalized: false,
        data: Vec::new(),
    })
    
}
