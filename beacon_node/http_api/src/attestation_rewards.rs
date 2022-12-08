use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::AttestationRewardsTBD;
use slog::Logger;
use types::ChainSpec;
use crate::Epoch;

pub fn compute_attestation_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    epoch: Epoch,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<AttestationRewardsTBD, Error> {

    let spec: ChainSpec = chain.spec;

    // Get which slot are part of the epoch

    // Use BlockReplayer to get the state of the slots

    // Calculate rewards

    // Create AttestationRewards with calculated rewards
    Ok(AttestationRewardsTBD{
        execution_optimistic: false,
        finalized: false,
        data: Vec::new(),
    })

}