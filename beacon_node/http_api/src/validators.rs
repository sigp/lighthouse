use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{
    self as api_types, ExecutionOptimisticFinalizedResponse, ValidatorBalanceData, ValidatorData,
    ValidatorId, ValidatorStatus,
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
                let ids_filter_set: Option<HashSet<&ValidatorId>> =
                    query_ids.as_ref().map(HashSet::from_iter);

                Ok((
                    state
                        .validators()
                        .iter()
                        .zip(state.balances().iter())
                        .enumerate()
                        // filter by validator id(s) if provided
                        .filter(|(index, (validator, _))| {
                            ids_filter_set.as_ref().map_or(true, |ids_set| {
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

                            let status_matches = query_statuses.as_ref().map_or(true, |statuses| {
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
                let ids_filter_set: Option<HashSet<&ValidatorId>> =
                    optional_ids.map(|f| HashSet::from_iter(f.iter()));

                Ok((
                    state
                        .validators()
                        .iter()
                        .zip(state.balances().iter())
                        .enumerate()
                        // filter by validator id(s) if provided
                        .filter(|(index, (validator, _))| {
                            ids_filter_set.as_ref().map_or(true, |ids_set| {
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
