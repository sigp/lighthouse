use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes, BeaconChainError};
use eth2::types::ValidatorId;
use eth2::lighthouse::SyncCommitteeReward;
use slog::{debug, Logger};
use state_processing::BlockReplayer;
use types::{BeaconState, SignedBlindedBeaconBlock};
use warp_utils::reject::{beacon_chain_error, custom_not_found};
use crate::{BlockId, ExecutionOptimistic};

pub fn compute_sync_committee_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<(Option<Vec<SyncCommitteeReward>>, ExecutionOptimistic), warp::Rejection> {


    let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

    let mut state = get_state_before_applying_block(chain.clone(), block.clone())?;

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
                            

    Ok((data, execution_optimistic))

    
}

fn get_state_before_applying_block<T:BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block: SignedBlindedBeaconBlock<T::EthSpec>
) -> Result<BeaconState<T::EthSpec>, warp::reject::Rejection> {

    let parent_block: SignedBlindedBeaconBlock<T::EthSpec> = chain
        .get_blinded_block(&block.parent_root())
        .and_then(|maybe_block| {
            maybe_block.ok_or(BeaconChainError::MissingBeaconBlock(block.parent_root()))
        })
        .map_err(|e| {
            custom_not_found(format!("Parent block is not available! {:?}", e))
        })?;

    let parent_state = chain
        .get_state(&parent_block.state_root(), Some(parent_block.slot()))
        .and_then(|maybe_state| {
            maybe_state.ok_or(BeaconChainError::MissingBeaconState(parent_block.state_root()))
        })
        .map_err(|e| {
            custom_not_found(format!("Parent state is not available! {:?}", e))
        })?;

    let replayer = BlockReplayer::new(parent_state, &chain.spec)
        .no_signature_verification()
        .state_root_iter([Ok((parent_block.state_root(), parent_block.slot()))].into_iter())
        .minimal_block_root_verification()
        .apply_blocks(vec![], Some(block.slot()))
        .map_err(beacon_chain_error)?;

    Ok(replayer.into_state())
}
