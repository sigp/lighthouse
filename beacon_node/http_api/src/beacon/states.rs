use crate::StateId;
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::ResponseFilter;
use crate::validator::pubkey_to_validator_index;
use crate::version::{
    ResponseIncludesVersion, add_consensus_version_header,
    execution_optimistic_finalized_beacon_response,
};
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::types::{
    ValidatorBalancesRequestBody, ValidatorId, ValidatorIdentitiesRequestBody,
    ValidatorsRequestBody,
};
use std::sync::Arc;
use types::{AttestationShufflingId, BeaconStateError, CommitteeCache, EthSpec, RelativeEpoch};
use warp::filters::BoxedFilter;
use warp::{Filter, Reply};
use warp_utils::query::multi_key_query;

type BeaconStatesPath<T> = BoxedFilter<(
    StateId,
    TaskSpawner<<T as BeaconChainTypes>::EthSpec>,
    Arc<BeaconChain<T>>,
)>;

// GET beacon/states/{state_id}/pending_consolidations
pub fn get_beacon_state_pending_consolidations<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("pending_consolidations"))
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (data, execution_optimistic, finalized, fork_name) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                let Ok(consolidations) = state.pending_consolidations() else {
                                    return Err(warp_utils::reject::custom_bad_request(
                                        "Pending consolidations not found".to_string(),
                                    ));
                                };

                                Ok((
                                    consolidations.clone(),
                                    execution_optimistic,
                                    finalized,
                                    state.fork_name_unchecked(),
                                ))
                            },
                        )?;

                    execution_optimistic_finalized_beacon_response(
                        ResponseIncludesVersion::Yes(fork_name),
                        execution_optimistic,
                        finalized,
                        data,
                    )
                    .map(|res| warp::reply::json(&res).into_response())
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/pending_partial_withdrawals
pub fn get_beacon_state_pending_partial_withdrawals<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("pending_partial_withdrawals"))
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (data, execution_optimistic, finalized, fork_name) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                let Ok(withdrawals) = state.pending_partial_withdrawals() else {
                                    return Err(warp_utils::reject::custom_bad_request(
                                        "Pending withdrawals not found".to_string(),
                                    ));
                                };

                                Ok((
                                    withdrawals.clone(),
                                    execution_optimistic,
                                    finalized,
                                    state.fork_name_unchecked(),
                                ))
                            },
                        )?;

                    execution_optimistic_finalized_beacon_response(
                        ResponseIncludesVersion::Yes(fork_name),
                        execution_optimistic,
                        finalized,
                        data,
                    )
                    .map(|res| warp::reply::json(&res).into_response())
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/pending_deposits
pub fn get_beacon_state_pending_deposits<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("pending_deposits"))
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (data, execution_optimistic, finalized, fork_name) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                let Ok(deposits) = state.pending_deposits() else {
                                    return Err(warp_utils::reject::custom_bad_request(
                                        "Pending deposits not found".to_string(),
                                    ));
                                };

                                Ok((
                                    deposits.clone(),
                                    execution_optimistic,
                                    finalized,
                                    state.fork_name_unchecked(),
                                ))
                            },
                        )?;

                    execution_optimistic_finalized_beacon_response(
                        ResponseIncludesVersion::Yes(fork_name),
                        execution_optimistic,
                        finalized,
                        data,
                    )
                    .map(|res| warp::reply::json(&res).into_response())
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/randao?epoch
pub fn get_beacon_state_randao<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("randao"))
        .and(warp::query::<eth2::types::RandaoQuery>())
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query: eth2::types::RandaoQuery| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (randao, execution_optimistic, finalized) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                let epoch = query.epoch.unwrap_or_else(|| state.current_epoch());
                                let randao = *state.get_randao_mix(epoch).map_err(|e| {
                                    warp_utils::reject::custom_bad_request(format!(
                                        "epoch out of range: {e:?}"
                                    ))
                                })?;
                                Ok((randao, execution_optimistic, finalized))
                            },
                        )?;

                    Ok(
                        eth2::types::GenericResponse::from(eth2::types::RandaoMix { randao })
                            .add_execution_optimistic_finalized(execution_optimistic, finalized),
                    )
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/sync_committees?epoch
pub fn get_beacon_state_sync_committees<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("sync_committees"))
        .and(warp::query::<eth2::types::SyncCommitteesQuery>())
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query: eth2::types::SyncCommitteesQuery| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (sync_committee, execution_optimistic, finalized) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                let current_epoch = state.current_epoch();
                                let epoch = query.epoch.unwrap_or(current_epoch);
                                Ok((
                                    state
                                        .get_built_sync_committee(epoch, &chain.spec)
                                        .cloned()
                                        .map_err(|e| match e {
                                            BeaconStateError::SyncCommitteeNotKnown { .. } => {
                                                warp_utils::reject::custom_bad_request(format!(
                                                    "state at epoch {} has no \
                                                     sync committee for epoch {}",
                                                    current_epoch, epoch
                                                ))
                                            }
                                            BeaconStateError::IncorrectStateVariant => {
                                                warp_utils::reject::custom_bad_request(format!(
                                                    "state at epoch {} is not activated for Altair",
                                                    current_epoch,
                                                ))
                                            }
                                            e => warp_utils::reject::beacon_state_error(e),
                                        })?,
                                    execution_optimistic,
                                    finalized,
                                ))
                            },
                        )?;

                    let validators = chain
                        .validator_indices(sync_committee.pubkeys.iter())
                        .map_err(warp_utils::reject::unhandled_error)?;

                    let validator_aggregates = validators
                        .chunks_exact(T::EthSpec::sync_subcommittee_size())
                        .map(|indices| eth2::types::SyncSubcommittee {
                            indices: indices.to_vec(),
                        })
                        .collect();

                    let response = eth2::types::SyncCommitteeByValidatorIndices {
                        validators,
                        validator_aggregates,
                    };

                    Ok(eth2::types::GenericResponse::from(response)
                        .add_execution_optimistic_finalized(execution_optimistic, finalized))
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/committees?slot,index,epoch
pub fn get_beacon_state_committees<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("committees"))
        .and(warp::query::<eth2::types::CommitteesQuery>())
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query: eth2::types::CommitteesQuery| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (data, execution_optimistic, finalized) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                let current_epoch = state.current_epoch();
                                let epoch = query.epoch.unwrap_or(current_epoch);

                                // Attempt to obtain the committee_cache from the beacon chain
                                let decision_slot = (epoch.saturating_sub(2u64))
                                    .end_slot(T::EthSpec::slots_per_epoch());
                                // Find the decision block and skip to another method on any kind
                                // of failure
                                let shuffling_id = if let Ok(Some(shuffling_decision_block)) =
                                    chain.block_root_at_slot(decision_slot, WhenSlotSkipped::Prev)
                                {
                                    Some(AttestationShufflingId {
                                        shuffling_epoch: epoch,
                                        shuffling_decision_block,
                                    })
                                } else {
                                    None
                                };

                                // Attempt to read from the chain cache if there exists a
                                // shuffling_id
                                let maybe_cached_shuffling = if let Some(shuffling_id) =
                                    shuffling_id.as_ref()
                                {
                                    chain
                                        .shuffling_cache
                                        .try_write_for(std::time::Duration::from_secs(1))
                                        .and_then(|mut cache_write| cache_write.get(shuffling_id))
                                        .and_then(|cache_item| cache_item.wait().ok())
                                } else {
                                    None
                                };

                                let committee_cache =
                                    if let Some(shuffling) = maybe_cached_shuffling {
                                        shuffling
                                    } else {
                                        let possibly_built_cache =
                                            match RelativeEpoch::from_epoch(current_epoch, epoch) {
                                                Ok(relative_epoch)
                                                    if state.committee_cache_is_initialized(
                                                        relative_epoch,
                                                    ) =>
                                                {
                                                    state.committee_cache(relative_epoch).cloned()
                                                }
                                                _ => CommitteeCache::initialized(
                                                    state,
                                                    epoch,
                                                    &chain.spec,
                                                ),
                                            }
                                            .map_err(
                                                |e| match e {
                                                    BeaconStateError::EpochOutOfBounds => {
                                                        let max_sprp =
                                                            T::EthSpec::slots_per_historical_root()
                                                                as u64;
                                                        let first_subsequent_restore_point_slot =
                                                            ((epoch.start_slot(
                                                                T::EthSpec::slots_per_epoch(),
                                                            ) / max_sprp)
                                                                + 1)
                                                                * max_sprp;
                                                        if epoch < current_epoch {
                                                            warp_utils::reject::custom_bad_request(
                                                                format!(
                                                        "epoch out of bounds, \
                                                                 try state at slot {}",
                                                        first_subsequent_restore_point_slot,
                                                    ),
                                                            )
                                                        } else {
                                                            warp_utils::reject::custom_bad_request(
                                                                "epoch out of bounds, \
                                                             too far in future"
                                                                    .into(),
                                                            )
                                                        }
                                                    }
                                                    _ => warp_utils::reject::unhandled_error(
                                                        BeaconChainError::from(e),
                                                    ),
                                                },
                                            )?;

                                        // Attempt to write to the beacon cache (only if the cache
                                        // size is not the default value).
                                        if chain.config.shuffling_cache_size
                                            != beacon_chain::shuffling_cache::DEFAULT_CACHE_SIZE
                                            && let Some(shuffling_id) = shuffling_id
                                            && let Some(mut cache_write) = chain
                                                .shuffling_cache
                                                .try_write_for(std::time::Duration::from_secs(1))
                                        {
                                            cache_write.insert_committee_cache(
                                                shuffling_id,
                                                &possibly_built_cache,
                                            );
                                        }

                                        possibly_built_cache
                                    };

                                // Use either the supplied slot or all slots in the epoch.
                                let slots =
                                    query.slot.map(|slot| vec![slot]).unwrap_or_else(|| {
                                        epoch.slot_iter(T::EthSpec::slots_per_epoch()).collect()
                                    });

                                // Use either the supplied committee index or all available indices.
                                let indices =
                                    query.index.map(|index| vec![index]).unwrap_or_else(|| {
                                        (0..committee_cache.committees_per_slot()).collect()
                                    });

                                let mut response = Vec::with_capacity(slots.len() * indices.len());

                                for slot in slots {
                                    // It is not acceptable to query with a slot that is not within the
                                    // specified epoch.
                                    if slot.epoch(T::EthSpec::slots_per_epoch()) != epoch {
                                        return Err(warp_utils::reject::custom_bad_request(
                                            format!("{} is not in epoch {}", slot, epoch),
                                        ));
                                    }

                                    for &index in &indices {
                                        let committee = committee_cache
                                            .get_beacon_committee(slot, index)
                                            .ok_or_else(|| {
                                                warp_utils::reject::custom_bad_request(format!(
                                                    "committee index {} does not exist in epoch {}",
                                                    index, epoch
                                                ))
                                            })?;

                                        response.push(eth2::types::CommitteeData {
                                            index,
                                            slot,
                                            validators: committee
                                                .committee
                                                .iter()
                                                .map(|i| *i as u64)
                                                .collect(),
                                        });
                                    }
                                }

                                Ok((response, execution_optimistic, finalized))
                            },
                        )?;
                    Ok(eth2::types::ExecutionOptimisticFinalizedResponse {
                        data,
                        execution_optimistic: Some(execution_optimistic),
                        finalized: Some(finalized),
                    })
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/validators/{validator_id}
pub fn get_beacon_state_validators_id<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::path::param::<ValidatorId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid validator ID".to_string(),
            ))
        }))
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             validator_id: ValidatorId| {
                // Prioritise requests for validators at the head. These should be fast to service
                // and could be required by the validator client.
                let priority = if let StateId(eth2::types::StateId::Head) = state_id {
                    Priority::P0
                } else {
                    Priority::P1
                };
                task_spawner.blocking_json_task(priority, move || {
                    let (data, execution_optimistic, finalized) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                let index_opt = match &validator_id {
                                    ValidatorId::PublicKey(pubkey) => pubkey_to_validator_index(
                                        &chain, state, pubkey,
                                    )
                                    .map_err(|e| {
                                        warp_utils::reject::custom_not_found(format!(
                                            "unable to access pubkey cache: {e:?}",
                                        ))
                                    })?,
                                    ValidatorId::Index(index) => Some(*index as usize),
                                };

                                Ok((
                                    index_opt
                                        .and_then(|index| {
                                            let validator = state.validators().get(index)?;
                                            let balance = *state.balances().get(index)?;
                                            let epoch = state.current_epoch();
                                            let far_future_epoch = chain.spec.far_future_epoch;

                                            Some(eth2::types::ValidatorData {
                                                index: index as u64,
                                                balance,
                                                status:
                                                    eth2::types::ValidatorStatus::from_validator(
                                                        validator,
                                                        epoch,
                                                        far_future_epoch,
                                                    ),
                                                validator: validator.clone(),
                                            })
                                        })
                                        .ok_or_else(|| {
                                            warp_utils::reject::custom_not_found(format!(
                                                "unknown validator: {}",
                                                validator_id
                                            ))
                                        })?,
                                    execution_optimistic,
                                    finalized,
                                ))
                            },
                        )?;

                    Ok(eth2::types::ExecutionOptimisticFinalizedResponse {
                        data,
                        execution_optimistic: Some(execution_optimistic),
                        finalized: Some(finalized),
                    })
                })
            },
        )
        .boxed()
}

// POST beacon/states/{state_id}/validators
pub fn post_beacon_state_validators<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query: ValidatorsRequestBody| {
                // Prioritise requests for validators at the head. These should be fast to service
                // and could be required by the validator client.
                let priority = if let StateId(eth2::types::StateId::Head) = state_id {
                    Priority::P0
                } else {
                    Priority::P1
                };
                task_spawner.blocking_json_task(priority, move || {
                    crate::validators::get_beacon_state_validators(
                        state_id,
                        chain,
                        &query.ids,
                        &query.statuses,
                    )
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/validators?id,status
pub fn get_beacon_state_validators<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(multi_key_query::<eth2::types::ValidatorsQuery>())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query_res: Result<eth2::types::ValidatorsQuery, warp::Rejection>| {
                // Prioritise requests for validators at the head. These should be fast to service
                // and could be required by the validator client.
                let priority = if let StateId(eth2::types::StateId::Head) = state_id {
                    Priority::P0
                } else {
                    Priority::P1
                };
                task_spawner.blocking_json_task(priority, move || {
                    let query = query_res?;
                    crate::validators::get_beacon_state_validators(
                        state_id,
                        chain,
                        &query.id,
                        &query.status,
                    )
                })
            },
        )
        .boxed()
}

// POST beacon/states/{state_id}/validator_identities
pub fn post_beacon_state_validator_identities<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("validator_identities"))
        .and(warp::path::end())
        .and(warp_utils::json::json_no_body())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query: ValidatorIdentitiesRequestBody| {
                // Prioritise requests for validators at the head. These should be fast to service
                // and could be required by the validator client.
                let priority = if let StateId(eth2::types::StateId::Head) = state_id {
                    Priority::P0
                } else {
                    Priority::P1
                };
                task_spawner.blocking_json_task(priority, move || {
                    crate::validators::get_beacon_state_validator_identities(
                        state_id,
                        chain,
                        Some(&query.ids),
                    )
                })
            },
        )
        .boxed()
}

// POST beacon/states/{state_id}/validator_balances
pub fn post_beacon_state_validator_balances<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("validator_balances"))
        .and(warp::path::end())
        .and(warp_utils::json::json_no_body())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query: ValidatorBalancesRequestBody| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    crate::validators::get_beacon_state_validator_balances(
                        state_id,
                        chain,
                        Some(&query.ids),
                    )
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/validator_balances?id
pub fn get_beacon_state_validator_balances<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("validator_balances"))
        .and(warp::path::end())
        .and(multi_key_query::<eth2::types::ValidatorBalancesQuery>())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query_res: Result<eth2::types::ValidatorBalancesQuery, warp::Rejection>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let query = query_res?;
                    crate::validators::get_beacon_state_validator_balances(
                        state_id,
                        chain,
                        query.id.as_deref(),
                    )
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/finality_checkpoints
pub fn get_beacon_state_finality_checkpoints<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("finality_checkpoints"))
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (data, execution_optimistic, finalized) = state_id
                        .map_state_and_execution_optimistic_and_finalized(
                            &chain,
                            |state, execution_optimistic, finalized| {
                                Ok((
                                    eth2::types::FinalityCheckpointsData {
                                        previous_justified: state.previous_justified_checkpoint(),
                                        current_justified: state.current_justified_checkpoint(),
                                        finalized: state.finalized_checkpoint(),
                                    },
                                    execution_optimistic,
                                    finalized,
                                ))
                            },
                        )?;

                    Ok(eth2::types::ExecutionOptimisticFinalizedResponse {
                        data,
                        execution_optimistic: Some(execution_optimistic),
                        finalized: Some(finalized),
                    })
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/fork
pub fn get_beacon_state_fork<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .clone()
        .and(warp::path("fork"))
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (fork, execution_optimistic, finalized) =
                        state_id.fork_and_execution_optimistic_and_finalized(&chain)?;
                    Ok(eth2::types::ExecutionOptimisticFinalizedResponse {
                        data: fork,
                        execution_optimistic: Some(execution_optimistic),
                        finalized: Some(finalized),
                    })
                })
            },
        )
        .boxed()
}

// GET beacon/states/{state_id}/root
pub fn get_beacon_state_root<T: BeaconChainTypes>(
    beacon_states_path: BeaconStatesPath<T>,
) -> ResponseFilter {
    beacon_states_path
        .and(warp::path("root"))
        .and(warp::path::end())
        .then(
            |state_id: StateId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (root, execution_optimistic, finalized) = state_id.root(&chain)?;
                    Ok(eth2::types::GenericResponse::from(
                        eth2::types::RootData::from(root),
                    ))
                    .map(|resp| {
                        resp.add_execution_optimistic_finalized(execution_optimistic, finalized)
                    })
                })
            },
        )
        .boxed()
}
