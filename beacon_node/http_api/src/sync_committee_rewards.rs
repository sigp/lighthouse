use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::{SyncCommitteeAttestationRewards, SyncCommitteeAttestationReward};
use slog::{debug, Logger};
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

    // TODO: retrieve post state here
    let mut state = chain
        .get_state(&state_root, Some(slot))
        .map_err(beacon_chain_error)?
        .ok_or_else(|| custom_bad_request(String::from("Unable to get state")))?;

    let reward_payload = chain
        .compute_sync_committee_rewards(block.message(), &mut state)
        .map_err(beacon_chain_error)?;

    let data = if reward_payload.is_empty() {
            None 
        } else if validators.is_empty() {
            Some(reward_payload)
        } else {
            Some(
                reward_payload
                    .into_iter()
                    .filter(|reward| {
                        validators
                            .iter()
                            .any(|validator| match validator {
                                ValidatorId::Index(i) => {
                                    reward.validator_index == *i
                                }
                                ValidatorId::PublicKey(pubkey) => {
                                    match state.get_validator_index(pubkey) {
                                        Ok(Some(i)) => { reward.validator_index == i as u64 }
                                        _ => { false }
                                    }
                                }
                            })
                    })
                    .collect::<Vec<SyncCommitteeAttestationReward>>()
                )
        };
                            

    Ok(SyncCommitteeAttestationRewards{
        execution_optimistic: None,
        finalized: None,
        data
    })

    
}
