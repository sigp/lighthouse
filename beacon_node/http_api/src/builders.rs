use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{BuilderData, BuilderId, BuilderStatus, ExecutionOptimisticFinalizedResponse};
use std::{collections::HashSet, sync::Arc};

pub fn get_beacon_state_builders<T: BeaconChainTypes>(
    state_id: StateId,
    chain: Arc<BeaconChain<T>>,
    query_ids: &Option<Vec<BuilderId>>,
    query_statuses: &Option<Vec<BuilderStatus>>,
) -> Result<ExecutionOptimisticFinalizedResponse<Vec<BuilderData>>, warp::Rejection> {
    let (data, execution_optimistic, finalized) = state_id
        .map_state_and_execution_optimistic_and_finalized(
            &chain,
            |state, execution_optimistic, finalized| {
                let builders = state.builders().map_err(|_| {
                    warp_utils::reject::custom_bad_request(
                        "Builders are not available for pre-Gloas states".to_string(),
                    )
                })?;
                let finalized_epoch = state.finalized_checkpoint().epoch;
                let far_future_epoch = chain.spec.far_future_epoch;

                let ids_filter_set: Option<HashSet<&BuilderId>> = query_ids
                    .as_ref()
                    .filter(|ids| !ids.is_empty())
                    .map(HashSet::from_iter);
                let statuses_filter_set: Option<HashSet<&BuilderStatus>> = query_statuses
                    .as_ref()
                    .filter(|statuses| !statuses.is_empty())
                    .map(HashSet::from_iter);

                Ok((
                    builders
                        .iter()
                        .enumerate()
                        .filter(|(index, builder)| {
                            ids_filter_set.as_ref().is_none_or(|ids| {
                                ids.contains(&BuilderId::PublicKey(builder.pubkey))
                                    || ids.contains(&BuilderId::Index(*index as u64))
                            })
                        })
                        .filter_map(|(index, builder)| {
                            let status = BuilderStatus::from_builder(
                                builder,
                                finalized_epoch,
                                far_future_epoch,
                            );
                            statuses_filter_set
                                .as_ref()
                                .is_none_or(|statuses| statuses.contains(&status))
                                .then(|| BuilderData {
                                    index: index as u64,
                                    status,
                                    builder: builder.clone(),
                                })
                        })
                        .collect(),
                    execution_optimistic,
                    finalized,
                ))
            },
        )?;

    Ok(ExecutionOptimisticFinalizedResponse {
        execution_optimistic: Some(execution_optimistic),
        finalized: Some(finalized),
        data,
    })
}
