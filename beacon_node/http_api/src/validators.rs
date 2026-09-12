use crate::state_id::StateId;
use crate::validator::pubkey_to_validator_index;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{
    self as api_types, ExecutionOptimisticFinalizedResponse, ValidatorBalanceData, ValidatorData,
    ValidatorId, ValidatorIdentityData, ValidatorStatus,
};
use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};
use types::{BeaconState, EthSpec, Validator};

// Map the ids (pubkeys or indices) to only indices as indices are easier to deal with
fn resolve_ids_to_indices<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    optional_ids: Option<&[ValidatorId]>,
) -> Result<Option<BTreeSet<usize>>, warp::Rejection> {
    let Some(ids) = optional_ids.filter(|ids| !ids.is_empty()) else {
        return Ok(None);
    };

    let mut indices = BTreeSet::new();

    for id in ids {
        let index_opt = match id {
            ValidatorId::Index(index) => usize::try_from(*index).ok(),
            ValidatorId::PublicKey(pubkey) => pubkey_to_validator_index(chain, state, pubkey)
                .map_err(|e| {
                    warp_utils::reject::custom_not_found(format!(
                        "unable to access pubkey cache: {e:?}",
                    ))
                })?,
        };
        if let Some(index) = index_opt {
            indices.insert(index);
        }
    }

    Ok(Some(indices))
}

// Yields an iterator of validators with its validator index
fn iter_validators<E: EthSpec>(
    state: &BeaconState<E>,
    indices: Option<BTreeSet<usize>>,
) -> Box<dyn Iterator<Item = (usize, &Validator)> + '_> {
    match indices {
        None => Box::new(state.validators().iter().enumerate()),
        Some(indices) => Box::new(
            indices
                .into_iter()
                .filter_map(move |index| Some((index, state.validators().get(index)?))),
        ),
    }
}

// Yields an iterator of validators with its validator index and balance
fn iter_validators_with_balances<E: EthSpec>(
    state: &BeaconState<E>,
    indices: Option<BTreeSet<usize>>,
) -> Box<dyn Iterator<Item = (usize, &Validator, u64)> + '_> {
    match indices {
        None => Box::new(
            state
                .validators()
                .iter()
                .zip(state.balances().iter())
                .enumerate()
                .map(|(index, (validator, balance))| (index, validator, *balance)),
        ),
        Some(indices) => Box::new(indices.into_iter().filter_map(move |index| {
            let validator = state.validators().get(index)?;
            let balance = *state.balances().get(index)?;
            Some((index, validator, balance))
        })),
    }
}

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

                let indices = resolve_ids_to_indices(&chain, state, query_ids.as_deref())?;

                let statuses_filter_set: Option<HashSet<&ValidatorStatus>> = query_statuses
                    .as_ref()
                    .filter(|list| !list.is_empty())
                    .map(HashSet::from_iter);

                Ok((
                    iter_validators_with_balances(state, indices)
                        // filter by status(es) if provided and map the result
                        .filter_map(|(index, validator, balance)| {
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
                                    balance,
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
                let indices = resolve_ids_to_indices(&chain, state, optional_ids)?;

                Ok((
                    iter_validators_with_balances(state, indices)
                        .map(|(index, _validator, balance)| ValidatorBalanceData {
                            index: index as u64,
                            balance,
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
                let indices = resolve_ids_to_indices(&chain, state, optional_ids)?;

                Ok((
                    iter_validators(state, indices)
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
