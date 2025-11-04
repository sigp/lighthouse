use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{
    self as api_types, ExecutionOptimisticFinalizedResponse, ValidatorBalanceData, ValidatorData,
    ValidatorId, ValidatorIdentityData, ValidatorStatus,
};
use std::{collections::HashSet, sync::Arc};

pub fn get_beacon_state_validators<T: BeaconChainTypes>(
    state_id: StateId,
    chain: Arc<BeaconChain<T>>,
    query_ids: &Option<Vec<ValidatorId>>,
    query_statuses: &Option<Vec<ValidatorStatus>>,
) -> Result<ExecutionOptimisticFinalizedResponse<Vec<ValidatorData>>, warp::Rejection> {
    let (data, execution_optimistic, finalized) = state_id
        .map_state_and_execution_optimistic_and_finalized(
            &chain,
            |state, execution_optimistic, finalized| {
                let epoch = state.current_epoch();
                let far_future_epoch = chain.spec.far_future_epoch;

                // Map [] to None, indicating that no filtering should be applied (return all
                // validators).
                let ids_filter_set: Option<HashSet<&ValidatorId>> = query_ids
                    .as_ref()
                    .filter(|list| !list.is_empty())
                    .map(HashSet::from_iter);

                let statuses_filter_set: Option<HashSet<&ValidatorStatus>> = query_statuses
                    .as_ref()
                    .filter(|list| !list.is_empty())
                    .map(HashSet::from_iter);

                Ok((
                    state
                        .validators()
                        .iter()
                        .zip(state.balances().iter())
                        .enumerate()
                        // filter by validator id(s) if provided
                        .filter(|(index, (validator, _))| {
                            ids_filter_set.as_ref().is_none_or(|ids_set| {
                                ids_set.contains(&ValidatorId::PublicKey(validator.pubkey))
                                    || ids_set.contains(&ValidatorId::Index(*index as u64))
                            })
                        })
                        // filter by status(es) if provided and map the result
                        .filter_map(|(index, (validator, balance))| {
                            let status = api_types::ValidatorStatus::from_validator(
                                validator,
                                epoch,
                                far_future_epoch,
                            );

                            let status_matches =
                                statuses_filter_set.as_ref().is_none_or(|statuses| {
                                    statuses.contains(&status)
                                        || statuses.contains(&status.superstatus())
                                });

                            if status_matches {
                                Some(ValidatorData {
                                    index: index as u64,
                                    balance: *balance,
                                    status,
                                    validator: validator.clone(),
                                })
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>(),
                    execution_optimistic,
                    finalized,
                ))
            },
        )?;

    Ok(ExecutionOptimisticFinalizedResponse {
        data,
        execution_optimistic: Some(execution_optimistic),
        finalized: Some(finalized),
    })
}

pub fn get_beacon_state_validator_balances<T: BeaconChainTypes>(
    state_id: StateId,
    chain: Arc<BeaconChain<T>>,
    optional_ids: Option<&[ValidatorId]>,
) -> Result<ExecutionOptimisticFinalizedResponse<Vec<ValidatorBalanceData>>, warp::Rejection> {
    let (data, execution_optimistic, finalized) = state_id
        .map_state_and_execution_optimistic_and_finalized(
            &chain,
            |state, execution_optimistic, finalized| {
                let ids_filter_set: Option<HashSet<&ValidatorId>> = match optional_ids {
                    // if optional_ids (the request data body) is [], returns a `None`, so that later when calling .is_none_or() will return True
                    // Hence, all validators will pass through .filter(), and balances of all validators are returned, in accordance to the spec
                    Some([]) => None,
                    Some(ids) => Some(HashSet::from_iter(ids.iter())),
                    None => None,
                };

                Ok((
                    state
                        .validators()
                        .iter()
                        .zip(state.balances().iter())
                        .enumerate()
                        // filter by validator id(s) if provided
                        .filter(|(index, (validator, _))| {
                            ids_filter_set.as_ref().is_none_or(|ids_set| {
                                ids_set.contains(&ValidatorId::PublicKey(validator.pubkey))
                                    || ids_set.contains(&ValidatorId::Index(*index as u64))
                            })
                        })
                        .map(|(index, (_, balance))| ValidatorBalanceData {
                            index: index as u64,
                            balance: *balance,
                        })
                        .collect::<Vec<_>>(),
                    execution_optimistic,
                    finalized,
                ))
            },
        )?;

    Ok(api_types::ExecutionOptimisticFinalizedResponse {
        data,
        execution_optimistic: Some(execution_optimistic),
        finalized: Some(finalized),
    })
}

pub fn get_beacon_state_validator_identities<T: BeaconChainTypes>(
    state_id: StateId,
    chain: Arc<BeaconChain<T>>,
    optional_ids: Option<&[ValidatorId]>,
) -> Result<ExecutionOptimisticFinalizedResponse<Vec<ValidatorIdentityData>>, warp::Rejection> {
    let (data, execution_optimistic, finalized) = state_id
        .map_state_and_execution_optimistic_and_finalized(
            &chain,
            |state, execution_optimistic, finalized| {
                let ids_filter_set: Option<HashSet<&ValidatorId>> = match optional_ids {
                    // Same logic as validator_balances endpoint above
                    Some([]) => None,
                    Some(ids) => Some(HashSet::from_iter(ids.iter())),
                    None => None,
                };

                Ok((
                    // From the BeaconState, extract the Validator data and convert it into ValidatorIdentityData type
                    state
                        .validators()
                        .iter()
                        .enumerate()
                        // filter by validator id(s) if provided
                        .filter(|(index, validator)| {
                            ids_filter_set.as_ref().is_none_or(|ids_set| {
                                ids_set.contains(&ValidatorId::PublicKey(validator.pubkey))
                                    || ids_set.contains(&ValidatorId::Index(*index as u64))
                            })
                        })
                        .map(|(index, validator)| ValidatorIdentityData {
                            index: index as u64,
                            pubkey: validator.pubkey,
                            activation_epoch: validator.activation_epoch,
                        })
                        .collect::<Vec<_>>(),
                    execution_optimistic,
                    finalized,
                ))
            },
        )?;

    Ok(api_types::ExecutionOptimisticFinalizedResponse {
        data,
        execution_optimistic: Some(execution_optimistic),
        finalized: Some(finalized),
    })
}
