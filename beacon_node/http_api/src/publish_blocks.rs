use crate::metrics;
use beacon_chain::validator_monitor::{get_block_delay_ms, timestamp_now};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError, CountUnrealized};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{crit, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BlindedPayload, BlobsSidecar, EthSpec, ExecPayload, ExecutionBlockHash,
    FullPayload, Hash256, SignedBeaconBlock, SignedBeaconBlockAndBlobsSidecar,
    SignedBeaconBlockEip4844,
};
use warp::Rejection;

/// Handles a request from the HTTP API for full blocks.
pub async fn publish_block<T: BeaconChainTypes>(
    block_root: Option<Hash256>,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
) -> Result<(), Rejection> {
    let seen_timestamp = timestamp_now();

    //FIXME(sean) have to move this to prior to publishing because it's included in the blobs sidecar message.
    //this may skew metrics
    let block_root = block_root.unwrap_or_else(|| block.canonical_root());

    // Send the block, regardless of whether or not it is valid. The API
    // specification is very clear that this is the desired behaviour.
    let message = if matches!(block.as_ref(), &SignedBeaconBlock::Eip4844(_)) {
        if let Some(sidecar) = chain.blob_cache.pop(&block_root) {
            PubsubMessage::BeaconBlockAndBlobsSidecars(Arc::new(SignedBeaconBlockAndBlobsSidecar {
                beacon_block: block.clone(),
                blobs_sidecar: Arc::new(sidecar),
            }))
        } else {
            //FIXME(sean): This should probably return a specific no-blob-cached error code, beacon API coordination required
            return Err(warp_utils::reject::broadcast_without_import(format!("no blob cached for block")));
        }
    } else {
        PubsubMessage::BeaconBlock(block.clone())
    };
    crate::publish_pubsub_message(network_tx, message)?;

    // Determine the delay after the start of the slot, register it with metrics.
    let delay = get_block_delay_ms(seen_timestamp, block.message(), &chain.slot_clock);
    metrics::observe_duration(&metrics::HTTP_API_BLOCK_BROADCAST_DELAY_TIMES, delay);

    match chain
        .process_block(block_root, block.clone(), CountUnrealized::True)
        .await
    {
        Ok(root) => {
            info!(
                log,
                "Valid block from HTTP API";
                "block_delay" => ?delay,
                "root" => format!("{}", root),
                "proposer_index" => block.message().proposer_index(),
                "slot" => block.slot(),
            );

            // Notify the validator monitor.
            chain.validator_monitor.read().register_api_block(
                seen_timestamp,
                block.message(),
                root,
                &chain.slot_clock,
            );

            // Update the head since it's likely this block will become the new
            // head.
            chain.recompute_head_at_current_slot().await;

            // Perform some logging to inform users if their blocks are being produced
            // late.
            //
            // Check to see the thresholds are non-zero to avoid logging errors with small
            // slot times (e.g., during testing)
            let crit_threshold = chain.slot_clock.unagg_attestation_production_delay();
            let error_threshold = crit_threshold / 2;
            if delay >= crit_threshold {
                crit!(
                    log,
                    "Block was broadcast too late";
                    "msg" => "system may be overloaded, block likely to be orphaned",
                    "delay_ms" => delay.as_millis(),
                    "slot" => block.slot(),
                    "root" => ?root,
                )
            } else if delay >= error_threshold {
                error!(
                    log,
                    "Block broadcast was delayed";
                    "msg" => "system may be overloaded, block may be orphaned",
                    "delay_ms" => delay.as_millis(),
                    "slot" => block.slot(),
                    "root" => ?root,
                )
            }

            Ok(())
        }
        Err(BlockError::BlockIsAlreadyKnown) => {
            info!(
                log,
                "Block from HTTP API already known";
                "block" => ?block.canonical_root(),
                "slot" => block.slot(),
            );
            Ok(())
        }
        Err(BlockError::RepeatProposal { proposer, slot }) => {
            warn!(
                log,
                "Block ignored due to repeat proposal";
                "msg" => "this can happen when a VC uses fallback BNs. \
                    whilst this is not necessarily an error, it can indicate issues with a BN \
                    or between the VC and BN.",
                "slot" => slot,
                "proposer" => proposer,
            );
            Ok(())
        }
        Err(e) => {
            let msg = format!("{:?}", e);
            error!(
                log,
                "Invalid block provided to HTTP API";
                "reason" => &msg
            );
            Err(warp_utils::reject::broadcast_without_import(msg))
        }
    }
}

/// Handles a request from the HTTP API for blinded blocks. This converts blinded blocks into full
/// blocks before publishing.
pub async fn publish_blinded_block<T: BeaconChainTypes>(
    block: SignedBeaconBlock<T::EthSpec, BlindedPayload<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
) -> Result<(), Rejection> {
    let block_root = block.canonical_root();
    let full_block = reconstruct_block(chain.clone(), block_root, block, log.clone()).await?;
    publish_block::<T>(
        Some(block_root),
        Arc::new(full_block),
        chain,
        network_tx,
        log,
    )
    .await
}

/// Deconstruct the given blinded block, and construct a full block. This attempts to use the
/// execution layer's payload cache, and if that misses, attempts a blind block proposal to retrieve
/// the full payload.
async fn reconstruct_block<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block: SignedBeaconBlock<T::EthSpec, BlindedPayload<T::EthSpec>>,
    log: Logger,
) -> Result<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>, Rejection> {
    let full_payload = if let Ok(payload_header) = block.message().body().execution_payload() {
        let el = chain.execution_layer.as_ref().ok_or_else(|| {
            warp_utils::reject::custom_server_error("Missing execution layer".to_string())
        })?;

        // If the execution block hash is zero, use an empty payload.
        let full_payload = if payload_header.block_hash() == ExecutionBlockHash::zero() {
            FullPayload::default_at_fork(
                chain
                    .spec
                    .fork_name_at_epoch(block.slot().epoch(T::EthSpec::slots_per_epoch())),
            )
            .into()
            // If we already have an execution payload with this transactions root cached, use it.
        } else if let Some(cached_payload) =
            el.get_payload_by_root(&payload_header.tree_hash_root())
        {
            info!(log, "Reconstructing a full block using a local payload"; "block_hash" => ?cached_payload.block_hash());
            cached_payload
            // Otherwise, this means we are attempting a blind block proposal.
        } else {
            let full_payload = el
                .propose_blinded_beacon_block(block_root, &block)
                .await
                .map_err(|e| {
                    warp_utils::reject::custom_server_error(format!(
                        "Blind block proposal failed: {:?}",
                        e
                    ))
                })?;
            info!(log, "Successfully published a block to the builder network"; "block_hash" => ?full_payload.block_hash());
            full_payload
        };

        Some(full_payload)
    } else {
        None
    };

    block.try_into_full_block(full_payload).ok_or_else(|| {
        warp_utils::reject::custom_server_error("Unable to add payload to block".to_string())
    })
}
