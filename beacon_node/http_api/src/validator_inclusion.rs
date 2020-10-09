use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::{
    lighthouse::{GlobalValidatorInclusionData, ValidatorInclusionData},
    types::ValidatorId,
};
use state_processing::per_epoch_processing::ValidatorStatuses;
use types::{Epoch, EthSpec};

/// Returns information about *all validators* (i.e., global) and how they performed during a given
/// epoch.
pub fn global_validator_inclusion_data<T: BeaconChainTypes>(
    epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<GlobalValidatorInclusionData, warp::Rejection> {
    let target_slot = epoch.end_slot(T::EthSpec::slots_per_epoch());

    let state = StateId::slot(target_slot).state(chain)?;

    let mut validator_statuses = ValidatorStatuses::new(&state, &chain.spec)
        .map_err(warp_utils::reject::beacon_state_error)?;
    validator_statuses
        .process_attestations(&state, &chain.spec)
        .map_err(warp_utils::reject::beacon_state_error)?;

    let totals = validator_statuses.total_balances;

    Ok(GlobalValidatorInclusionData {
        current_epoch_active_gwei: totals.current_epoch(),
        previous_epoch_active_gwei: totals.previous_epoch(),
        current_epoch_attesting_gwei: totals.current_epoch_attesters(),
        current_epoch_target_attesting_gwei: totals.current_epoch_target_attesters(),
        previous_epoch_attesting_gwei: totals.previous_epoch_attesters(),
        previous_epoch_target_attesting_gwei: totals.previous_epoch_target_attesters(),
        previous_epoch_head_attesting_gwei: totals.previous_epoch_head_attesters(),
    })
}

/// Returns information about a single validator and how it performed during a given epoch.
pub fn validator_inclusion_data<T: BeaconChainTypes>(
    epoch: Epoch,
    validator_id: &ValidatorId,
    chain: &BeaconChain<T>,
) -> Result<Option<ValidatorInclusionData>, warp::Rejection> {
    let target_slot = epoch.end_slot(T::EthSpec::slots_per_epoch());

    let mut state = StateId::slot(target_slot).state(chain)?;

    let mut validator_statuses = ValidatorStatuses::new(&state, &chain.spec)
        .map_err(warp_utils::reject::beacon_state_error)?;
    validator_statuses
        .process_attestations(&state, &chain.spec)
        .map_err(warp_utils::reject::beacon_state_error)?;

    state
        .update_pubkey_cache()
        .map_err(warp_utils::reject::beacon_state_error)?;

    let validator_index = match validator_id {
        ValidatorId::Index(index) => *index as usize,
        ValidatorId::PublicKey(pubkey) => {
            if let Some(index) = state
                .get_validator_index(pubkey)
                .map_err(warp_utils::reject::beacon_state_error)?
            {
                index
            } else {
                return Ok(None);
            }
        }
    };

    Ok(validator_statuses
        .statuses
        .get(validator_index)
        .map(|vote| ValidatorInclusionData {
            is_slashed: vote.is_slashed,
            is_withdrawable_in_current_epoch: vote.is_withdrawable_in_current_epoch,
            is_active_in_current_epoch: vote.is_active_in_current_epoch,
            is_active_in_previous_epoch: vote.is_active_in_previous_epoch,
            current_epoch_effective_balance_gwei: vote.current_epoch_effective_balance,
            is_current_epoch_attester: vote.is_current_epoch_attester,
            is_current_epoch_target_attester: vote.is_current_epoch_target_attester,
            is_previous_epoch_attester: vote.is_previous_epoch_attester,
            is_previous_epoch_target_attester: vote.is_previous_epoch_target_attester,
            is_previous_epoch_head_attester: vote.is_previous_epoch_head_attester,
        }))
}
