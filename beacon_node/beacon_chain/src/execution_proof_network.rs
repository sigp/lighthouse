use crate::{BeaconChain, BeaconChainTypes, BlockProductionError};
use std::sync::Arc;
use tracing::{debug, info, warn};
use types::{
    BeaconBlockRef, BeaconStateError, ExecutionPayload, ExecutionProofSubnetId,
    ExecPayload, FullPayload, FullPayloadRef, Hash256,
};

/// Spawn a background task to generate and store execution proofs with publishing via callback
/// This provides a clean interface for both HTTP API (publish_blocks) and gossip processing (process_block)
pub fn spawn_proof_generation_task_with_publishing<T, F>(
    chain: &Arc<BeaconChain<T>>,
    block: BeaconBlockRef<'_, T::EthSpec, FullPayload<T::EthSpec>>,
    block_root: Hash256,
    publish_fn: F,
    task_name: &'static str,
)
where
    T: BeaconChainTypes,
    F: Fn(ExecutionProofSubnetId, types::ExecutionProof) + Send + 'static,
{
    let chain_clone = chain.clone();

    // Extract the concrete ExecutionPayload from the BeaconBlock
    let payload = match extract_execution_payload(block) {
        Ok(payload) => payload,
        Err(e) => {
            warn!(
                "Failed to extract execution payload for proof generation: {:?}",
                e
            );
            return;
        }
    };

    // Spawn the proof generation task in the background
    chain.task_executor.spawn(
        async move {
            let execution_block_hash = payload.block_hash();

            info!(
                execution_block_hash = ?execution_block_hash,
                block_root = ?block_root,
                "Starting execution proof generation"
            );

            // Simulate execution witness data (in production, this would come from EL)
            let witness = format!("dummy_witness_for_block_{:?}", execution_block_hash).into_bytes();

            // Get configured subnets for proof generation
            let proof_subnets = get_configured_proof_subnets(&chain_clone);

            debug!(
                execution_block_hash = ?execution_block_hash,
                subnet_count = proof_subnets.len(),
                subnets = ?proof_subnets,
                "Generating proofs for configured subnets"
            );

            // Generate and store a proof for each subnet
            for subnet_id in proof_subnets {
                let proof_id = match ExecutionProofSubnetId::new(subnet_id) {
                    Ok(id) => id,
                    Err(e) => {
                        debug!(subnet_id, error = %e, "Invalid subnet ID, skipping");
                        continue;
                    }
                };

                // Generate proof using the execution_proof_generation module
                let proof = crate::execution_proof_generation::generate_proof(
                    block_root, &payload, &witness, proof_id,
                )
                .await;

                let verified_proof = match crate::execution_proof_verification::GossipVerifiedExecutionProof::<
                    T,
                >::new(Arc::new(proof.clone()), proof_id, &chain_clone)
                {
                    Ok(verified) => verified,
                    Err(e) => {
                        warn!(
                            execution_block_hash = ?execution_block_hash,
                            subnet_id,
                            error = ?e,
                            "Failed to verify locally generated execution proof"
                        );
                        continue; // Skip this proof and continue with next subnet
                    }
                };

                // Store in local DA checker
                match chain_clone
                    .data_availability_checker
                    .put_gossip_verified_execution_proofs(block_root, std::iter::once(verified_proof))
                {
                    Ok(_) => {
                        debug!(
                            execution_block_hash = ?execution_block_hash,
                            subnet_id,
                            "Generated and stored execution proof locally"
                        );
                        // Let the caller handle publishing via their specific network interface
                        publish_fn(proof_id, proof);
                    }
                    Err(e) => {
                        warn!(
                            execution_block_hash = ?execution_block_hash,
                            subnet_id,
                            error = ?e,
                            "Failed to store generated execution proof"
                        );
                    }
                }
            }
        },
        task_name,
    );
}

/// Get configured proof subnets for this node
pub fn get_configured_proof_subnets<T: BeaconChainTypes>(chain: &Arc<BeaconChain<T>>) -> Vec<u64> {
    // TODO: For now, the node will generate proofs for all available subnets.
    // TODO: In the future, they should be able to configure this for proofs
    // TODO: they can generate for. Mainly for altruistic nodes that want to
    // TODO: seed the network.
    // TODO(question): Check if there are any assumptions on the proof being deterministic
    // TODO: ie whether its okay that two nodes generate two valid proofs for the same payload.
    if chain.config.generate_execution_proofs {
        (0..types::execution_proof_subnet_id::MAX_EXECUTION_PROOF_SUBNETS).collect()
    } else {
        vec![]
    }
}

/// Extract execution payload from BeaconBlockRef for proof generation
pub fn extract_execution_payload<E: types::EthSpec>(
    block: BeaconBlockRef<'_, E, FullPayload<E>>,
) -> Result<ExecutionPayload<E>, BeaconStateError> {
    let payload_ref = block.body().execution_payload()?;
    Ok(match payload_ref {
        FullPayloadRef::Bellatrix(payload) => {
            ExecutionPayload::Bellatrix(payload.execution_payload.clone())
        }
        FullPayloadRef::Capella(payload) => {
            ExecutionPayload::Capella(payload.execution_payload.clone())
        }
        FullPayloadRef::Deneb(payload) => {
            ExecutionPayload::Deneb(payload.execution_payload.clone())
        }
        FullPayloadRef::Electra(payload) => {
            ExecutionPayload::Electra(payload.execution_payload.clone())
        }
        FullPayloadRef::Fulu(payload) => ExecutionPayload::Fulu(payload.execution_payload.clone()),
        FullPayloadRef::Gloas(payload) => {
            ExecutionPayload::Gloas(payload.execution_payload.clone())
        }
    })
}