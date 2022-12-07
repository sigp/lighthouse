use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::AttestationRewardsTBD;
use slog::Logger;
use crate::BlockId;

pub fn compute_attestation_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_id: BlockId,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<AttestationRewardsTBD, Error> {

    // Create AttestationRewards with calculated rewards
    Ok(AttestationRewardsTBD{
        execution_optimistic: false,
        finalized: false,
        data: Vec::new(),
    })

}