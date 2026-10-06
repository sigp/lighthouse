use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    self, ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter,
};
use beacon_chain::execution_proof_verification::Error as ExecutionProofError;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes};
use bytes::Bytes;
use eth2::types::Failure;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::Decode;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};
use types::execution::SignedExecutionProof;
use warp::{Filter, Reply};

/// POST beacon/execution_proofs (SSZ)
///
/// Where EIP-8025 proofs enter the network: a prover signs and submits on its own schedule.
pub(crate) fn post_beacon_execution_proofs<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_proofs"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |body_bytes: Bytes,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    publish_execution_proofs(&chain, &network_tx, body_bytes).await
                })
            },
        )
        .boxed()
}

async fn publish_execution_proofs<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    body_bytes: Bytes,
) -> Result<warp::reply::Response, warp::Rejection> {
    let proofs = Vec::<SignedExecutionProof>::from_ssz_bytes(&body_bytes)
        .map_err(|e| warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}")))?;

    let mut failures = vec![];
    let mut num_already_known = 0;
    for (index, proof) in proofs.into_iter().enumerate() {
        let proof = Arc::new(proof);
        match chain.verify_execution_proof_for_gossip(proof.clone()).await {
            Ok(verified) => {
                debug!(
                    block_root = ?proof.beacon_block_root(),
                    proof_type = proof.proof_type(),
                    "Publishing submitted execution proof"
                );
                utils::publish_pubsub_message(network_tx, PubsubMessage::ExecutionProof(proof))?;

                // This may be the proof the block's envelope was waiting on.
                match chain
                    .check_execution_proof_availability_and_import(verified)
                    .await
                {
                    Ok(AvailabilityProcessingStatus::Imported(slot, block_root)) => {
                        info!(
                            ?block_root,
                            %slot,
                            "Execution payload envelope imported after execution proof"
                        );
                        chain.recompute_head_at_current_slot().await;
                    }
                    Ok(AvailabilityProcessingStatus::MissingComponents(..)) => {}
                    Err(e) => {
                        warn!(
                            error = ?e,
                            request_index = index,
                            "Could not act on submitted execution proof"
                        );
                    }
                }
            }
            // Not a failure: a relay retrying the same bytes has nothing to do differently. The
            // record predates the engine's verdict, so a retry of a rejected proof lands here too.
            Err(
                ExecutionProofError::ProofAlreadySeen | ExecutionProofError::ValidProofAlreadyKnown,
            ) => num_already_known += 1,
            Err(e) => {
                debug!(
                    error = ?e,
                    request_index = index,
                    "Failure verifying submitted execution proof"
                );
                failures.push(Failure::new(index, format!("{e:?}")));
            }
        }
    }

    if num_already_known > 0 {
        debug!(
            count = num_already_known,
            "Some submitted execution proofs already known"
        );
    }

    if failures.is_empty() {
        Ok(warp::reply::reply().into_response())
    } else {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing execution proofs".to_string(),
            failures,
        ))
    }
}
