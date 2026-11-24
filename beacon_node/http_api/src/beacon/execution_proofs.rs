use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    self, ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter,
};
use beacon_chain::execution_proof_verification::{Error as ExecutionProofError, ProofSource};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bytes::Bytes;
use eth2::types::Failure;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::Decode;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};
use types::execution::SignedExecutionProofEnvelope;
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
    // Only enabled with a proof engine.
    if chain.proof_engine.is_none() {
        return Err(warp::reject::not_found());
    }

    let proofs = Vec::<SignedExecutionProofEnvelope>::from_ssz_bytes(&body_bytes)
        .map_err(|e| warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}")))?;

    let mut failures = vec![];
    let mut num_already_known = 0;
    for (index, proof) in proofs.into_iter().enumerate() {
        let proof = Arc::new(proof);
        let beacon_block_root = proof.beacon_block_root();
        let proof_type = proof.proof_type();
        match chain
            .verify_execution_proof_for_gossip(proof.clone(), ProofSource::Http)
            .await
        {
            Ok(_verified) => {
                debug!(
                    %beacon_block_root,
                    proof_type,
                    "Publishing submitted execution proof"
                );
                utils::publish_pubsub_message(network_tx, PubsubMessage::ExecutionProof(proof))?;

                // This may be the proof the block's payload was waiting on.
                if let Err(error) = chain.promote_payload_if_proven(beacon_block_root).await {
                    warn!(
                        %beacon_block_root,
                        proof_type,
                        ?error,
                        request_index = index,
                        "Could not validate payload after execution proof"
                    );
                }
            }
            // Not a failure: a verified proof of this type is already known.
            Err(ExecutionProofError::ValidProofAlreadyKnown) => num_already_known += 1,
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
