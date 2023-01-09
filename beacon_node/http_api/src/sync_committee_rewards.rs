use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes, BeaconChainError};
use eth2::types::ValidatorId;
use eth2::lighthouse::{SyncCommitteeRewards, SyncCommitteeReward};
use slog::{debug, Logger};
use state_processing::BlockReplayer;
use types::{BeaconState, SignedBlindedBeaconBlock};
use warp_utils::reject::beacon_chain_error;
use crate::BlockId;

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<SyncCommitteeRewards, warp::Rejection> {


    let (block, _) = block_id.blinded_block(&chain)?;

    let mut state = get_state_before_applying_block(chain.clone(), block.clone())
        .map_err(beacon_chain_error)?;

    let reward_payload = chain
        .compute_sync_committee_rewards(block.message(), &mut state)
        .map_err(beacon_chain_error)?;

    let data = if reward_payload.is_empty() {
            debug!(log, "compute_sync_committee_rewards returned empty");
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
                    .collect::<Vec<SyncCommitteeReward>>()
                )
        };
                            

    Ok(SyncCommitteeRewards{
        execution_optimistic: None,
        finalized: None,
        data
    })

    
}

fn get_state_before_applying_block<T:BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block: SignedBlindedBeaconBlock<T::EthSpec>
) -> Result<BeaconState<T::EthSpec>, BeaconChainError> {

    let parent_block: SignedBlindedBeaconBlock<T::EthSpec> = chain
        .get_blinded_block(&block.parent_root())?
        .ok_or_else(|| BeaconChainError::SyncCommitteeRewardsSyncError)?;


    let parent_state = chain
        .get_state(&parent_block.state_root(), Some(parent_block.slot()))?
        .ok_or_else(|| BeaconChainError::SyncCommitteeRewardsSyncError)?;

    let replayer = BlockReplayer::new(parent_state, &chain.spec)
        .no_signature_verification()
        .state_root_iter([Ok((parent_block.state_root(), parent_block.slot()))].into_iter())
        .minimal_block_root_verification()
        .apply_blocks(vec![], Some(block.slot()))
        .map_err(|_: BeaconChainError| BeaconChainError::SyncCommitteeRewardsSyncError)?;

    Ok(replayer.into_state())
}
