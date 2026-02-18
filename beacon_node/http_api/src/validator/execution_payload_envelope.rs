use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    ChainFilter, EthV1Filter, NotWhileSyncingFilter, ResponseFilter, TaskSpawnerFilter,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::beacon_response::{EmptyMetadata, ForkVersionedResponse};
use eth2::types::Accept;
use ssz::Encode;
use std::sync::Arc;
use tracing::debug;
use types::Slot;
use warp::http::Response;
use warp::{Filter, Rejection};

// GET validator/execution_payload_envelope/{slot}/{builder_index}
pub fn get_validator_execution_payload_envelope<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("execution_payload_envelope"))
        .and(warp::path::param::<Slot>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid slot".to_string(),
            ))
        }))
        .and(warp::path::param::<u64>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid builder_index".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(warp::header::optional::<Accept>("accept"))
        .and(not_while_syncing_filter)
        .and(task_spawner_filter)
        .and(chain_filter)
        .then(
            |slot: Slot,
             // TODO(gloas) we're only doing local building
             // we'll need to implement builder index logic
             // eventually.
             _builder_index: u64,
             accept_header: Option<Accept>,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    debug!(?slot, "Execution payload envelope request from HTTP API");

                    not_synced_filter?;

                    // Get the envelope from the pending cache (local building only)
                    let envelope = chain
                        .pending_payload_envelopes
                        .read()
                        .get(slot)
                        .cloned()
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "Execution payload envelope not available for slot {slot}"
                            ))
                        })?;

                    let fork_name = chain.spec.fork_name_at_slot::<T::EthSpec>(slot);

                    match accept_header {
                        Some(Accept::Ssz) => Response::builder()
                            .status(200)
                            .header("Content-Type", "application/octet-stream")
                            .header("Eth-Consensus-Version", fork_name.to_string())
                            .body(envelope.as_ssz_bytes().into())
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "Failed to build SSZ response: {e}"
                                ))
                            }),
                        _ => {
                            let json_response = ForkVersionedResponse {
                                version: fork_name,
                                metadata: EmptyMetadata {},
                                data: envelope,
                            };
                            Response::builder()
                                .status(200)
                                .header("Content-Type", "application/json")
                                .header("Eth-Consensus-Version", fork_name.to_string())
                                .body(
                                    serde_json::to_string(&json_response)
                                        .map_err(|e| {
                                            warp_utils::reject::custom_server_error(format!(
                                                "Failed to serialize response: {e}"
                                            ))
                                        })?
                                        .into(),
                                )
                                .map_err(|e| {
                                    warp_utils::reject::custom_server_error(format!(
                                        "Failed to build JSON response: {e}"
                                    ))
                                })
                        }
                    }
                })
            },
        )
        .boxed()
}
