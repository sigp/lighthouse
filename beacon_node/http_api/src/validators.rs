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

// Collects `f(index, validator)` over the requested validators, or over all validators when
// `indices` is `None`.
fn collect_validators<E: EthSpec, R>(
    state: &BeaconState<E>,
    indices: Option<BTreeSet<usize>>,
    mut f: impl FnMut(usize, &Validator) -> Option<R>,
) -> Vec<R> {
    match indices {
        None => state
            .validators()
            .iter()
            .enumerate()
            .filter_map(|(index, validator)| f(index, validator))
            .collect(),
        Some(indices) => indices
            .into_iter()
            .filter_map(|index| f(index, state.validators().get(index)?))
            .collect(),
    }
}

// As `collect_validators`, but also passes each validator's balance to `f`.
fn collect_validators_with_balances<E: EthSpec, R>(
    state: &BeaconState<E>,
    indices: Option<BTreeSet<usize>>,
    mut f: impl FnMut(usize, &Validator, u64) -> Option<R>,
) -> Vec<R> {
    match indices {
        None => state
            .validators()
            .iter()
            .zip(state.balances().iter())
            .enumerate()
            .filter_map(|(index, (validator, balance))| f(index, validator, *balance))
            .collect(),
        Some(indices) => indices
            .into_iter()
            .filter_map(|index| {
                let validator = state.validators().get(index)?;
                let balance = *state.balances().get(index)?;
                f(index, validator, balance)
            })
            .collect(),
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
                    // filter by status(es) if provided and map the result
                    collect_validators_with_balances(
                        state,
                        indices,
                        |index, validator, balance| {
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
                        },
                    ),
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
                    collect_validators_with_balances(
                        state,
                        indices,
                        |index, _validator, balance| {
                            Some(ValidatorBalanceData {
                                index: index as u64,
                                balance,
                            })
                        },
                    ),
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
                    collect_validators(state, indices, |index, validator| {
                        Some(ValidatorIdentityData {
                            index: index as u64,
                            pubkey: validator.pubkey,
                            activation_epoch: validator.activation_epoch,
                        })
                    }),
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
