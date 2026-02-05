use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    ChainFilter, EthV1Filter, NotWhileSyncingFilter, ResponseFilter, TaskSpawnerFilter,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::Accept;
use std::sync::Arc;
use tracing::debug;
use types::Slot;
use warp::{Filter, Rejection};

// GET validator/execution_payload_bid/
#[allow(dead_code)]
pub fn get_validator_execution_payload_bid<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("execution_payload_bid"))
        .and(warp::path::param::<Slot>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid slot".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(warp::header::optional::<Accept>("accept"))
        .and(not_while_syncing_filter)
        .and(task_spawner_filter)
        .and(chain_filter)
        .then(
            |slot: Slot,
             _accept_header: Option<Accept>,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             _chain: Arc<BeaconChain<T>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    debug!(
                        ?slot,
                        "Execution paylaod bid production request from HTTP API"
                    );

                    not_synced_filter?;

                    todo!()
                })
            },
        )
        .boxed()
}
