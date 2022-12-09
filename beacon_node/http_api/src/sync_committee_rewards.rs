use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::SyncCommitteeAttestationRewards;
use slog::Logger;
use state_processing::{per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards};
<<<<<<< HEAD
=======
use warp_utils::reject::{beacon_chain_error, custom_bad_request};
>>>>>>> 0f352220 (Changed fields to optional in sync_committee_attestation_rewards)
use crate::BlockId;

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
<<<<<<< HEAD
) -> Result<SyncCommitteeAttestationRewards, E> {
=======
) -> Result<SyncCommitteeAttestationRewards, warp::Rejection> {
>>>>>>> 0f352220 (Changed fields to optional in sync_committee_attestation_rewards)

    let spec = &chain.spec;

    let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

    let slot = block.slot();

    let state_root = block.state_root();

<<<<<<< HEAD
    // Technically we should use the pre-block state, but it won't matter because
    // compute_sync_aggregate_rewards() only uses state.get_total_active_balance() which only changes on epoch boundaries.
    // So, the "wrong" state will still give the same result.
    let state = chain.get_state(&state_root, Some(slot))?.unwrap();

    let (_, rewards) = compute_sync_aggregate_rewards(&state, &spec)?;
=======
    let state = chain
        .get_state(&state_root, Some(slot))
        .map_err(beacon_chain_error)?
        .ok_or_else(|| custom_bad_request(String::from("Unable to get state")))?;

    let (participant_reward, _) = compute_sync_aggregate_rewards(&state, spec)
        .map_err(|_| custom_bad_request(String::from("Unable to get rewards")))?;


>>>>>>> 0f352220 (Changed fields to optional in sync_committee_attestation_rewards)
    
    // Create SyncCommitteeRewards with calculated rewards
    Ok(SyncCommitteeAttestationRewards{
        execution_optimistic: None,
        finalized: None,
        data: Some(vec![])
    })
    
}
