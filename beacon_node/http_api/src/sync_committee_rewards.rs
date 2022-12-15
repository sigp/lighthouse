use std::collections::HashMap;
use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::{SyncCommitteeAttestationRewards, SyncCommitteeAttestationReward};
use slog::{debug, Logger};
use state_processing::per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards;
use warp_utils::reject::{beacon_chain_error, custom_bad_request};
use crate::BlockId;

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<SyncCommitteeAttestationRewards, warp::Rejection> {

    let spec = &chain.spec;

    let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

    let slot = block.slot();

    let state_root = block.state_root();

    let sync_aggregate = block
        .message()
        .body()
        .sync_aggregate()
        .map_err(|_| custom_bad_request(String::from("Unable to get sync aggregate")))?;

    // Technically we should use the pre-block state, but it won't matter because
    // compute_sync_aggregate_rewards() only uses state.get_total_active_balance() which only changes on epoch boundaries.
    // So, the "wrong" state will still give the same result.
    let mut state = chain
        .get_state(&state_root, Some(slot))
        .map_err(beacon_chain_error)?
        .ok_or_else(|| custom_bad_request(String::from("Unable to get state")))?;

    let sync_committee = state
        .current_sync_committee()
        .map_err(|_| custom_bad_request(String::from("Unable to get participants")))?
        .clone();

    let sync_committee_indices = state
        .get_sync_committee_indices(&sync_committee)
        .map_err(|_| custom_bad_request(String::from("Unable to get participant indices")))?;

    debug!(
        log,
        "Retrieving sync committee attestation rewards";
        "state_root" => ?state_root,
        "slot" => slot,
        );

    let (participant_reward_value, _) = compute_sync_aggregate_rewards(&state, spec)
        .map_err(|_| custom_bad_request(format!("Unable to get sync aggregate rewards at state root {:?}", state_root)))?;

    debug!(
        log,
        "Retrived sync committee attestation reward value";
        "reward_value" => participant_reward_value
        );


    let mut balances = sync_committee_indices
        .iter()
        .map(|i| (*i, state.balances()[*i]))
        .collect::<HashMap<usize, u64>>();

    let mut total_proposer_rewards = 0;

    for (validator_index, participant_bit) in sync_committee_indices.iter().zip(sync_aggregate.sync_committee_bits.iter()) {
        let mut participant_balance = balances.get_mut(validator_index);
        if participant_bit {
            participant_balance.get_or_insert(&mut 0).saturating_add(participant_reward_value);
            // TODO: Update proposer reward at proposer_index
        } else {
            participant_balance.get_or_insert(&mut 0).saturating_sub(participant_reward_value);
        }
    }

    let data = if sync_committee.pubkeys.is_empty() { 
        None
        } else {
            Some(
                balances.iter().map(|(i, new_balance)| {
                    let reward = *new_balance as i64 - state.balances()[*i] as i64 - total_proposer_rewards;
                    SyncCommitteeAttestationReward {
                        validator_index: *i as u64,
                        reward
                    }
                })
                .collect()
            )
        };

    Ok(SyncCommitteeAttestationRewards{
        execution_optimistic: None,
        finalized: None,
        data
    })
    
}
