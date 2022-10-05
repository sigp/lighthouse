use crate::metrics;
use beacon_chain::validator_monitor::{get_block_delay_ms, get_slot_delay_ms, timestamp_now};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError, CountUnrealized};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{crit, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tree_hash::TreeHash;
use types::{
    BlindedPayload, ExecPayload, ExecutionBlockHash, ExecutionPayload, FullPayload, Hash256,
    SignedBeaconBlock, SignedBlobsSidecar,
};
use warp::Rejection;

/// Handles a request from the HTTP API for full blocks.
pub async fn publish_blobs<T: BeaconChainTypes>(
    blobs_sidecar: Arc<SignedBlobsSidecar<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
) -> Result<(), Rejection> {
    let seen_timestamp = timestamp_now();

    // Send the blob, regardless of whether or not it is valid. The API
    // specification is very clear that this is the desired behaviour.
    crate::publish_pubsub_message(
        network_tx,
        PubsubMessage::BlobsSidecars(blobs_sidecar.clone()),
    )?;

    // Determine the delay after the start of the slot, register it with metrics.
    let delay = get_slot_delay_ms(
        seen_timestamp,
        blobs_sidecar.message.beacon_block_slot,
        &chain.slot_clock,
    );
    metrics::observe_duration(&metrics::HTTP_API_BLOB_BROADCAST_DELAY_TIMES, delay);

    //FIXME(sean) process blobs
    // match chain
    //     .process_block(blobs_sidecar.clone(), CountUnrealized::True)
    //     .await
    // {
    //     Ok(root) => {
    //         info!(
    //             log,
    //             "Valid block from HTTP API";
    //             "block_delay" => ?delay,
    //             "root" => format!("{}", root),
    //             "proposer_index" => block.message().proposer_index(),
    //             "slot" => block.slot(),
    //         );
    //
    //         // Notify the validator monitor.
    //         chain.validator_monitor.read().register_api_block(
    //             seen_timestamp,
    //             blobs_sidecar.message(),
    //             root,
    //             &chain.slot_clock,
    //         );
    //
    //         // Update the head since it's likely this block will become the new
    //         // head.
    //         chain.recompute_head_at_current_slot().await;
    //
    //         // Perform some logging to inform users if their blocks are being produced
    //         // late.
    //         //
    //         // Check to see the thresholds are non-zero to avoid logging errors with small
    //         // slot times (e.g., during testing)
    //         let crit_threshold = chain.slot_clock.unagg_attestation_production_delay();
    //         let error_threshold = crit_threshold / 2;
    //         if delay >= crit_threshold {
    //             crit!(
    //                 log,
    //                 "Block was broadcast too late";
    //                 "msg" => "system may be overloaded, block likely to be orphaned",
    //                 "delay_ms" => delay.as_millis(),
    //                 "slot" => block.slot(),
    //                 "root" => ?root,
    //             )
    //         } else if delay >= error_threshold {
    //             error!(
    //                 log,
    //                 "Block broadcast was delayed";
    //                 "msg" => "system may be overloaded, block may be orphaned",
    //                 "delay_ms" => delay.as_millis(),
    //                 "slot" => block.slot(),
    //                 "root" => ?root,
    //             )
    //         }
    //
    //         Ok(())
    //     }
    //     Err(BlockError::BlockIsAlreadyKnown) => {
    //         info!(
    //             log,
    //             "Block from HTTP API already known";
    //             "block" => ?block.canonical_root(),
    //             "slot" => block.slot(),
    //         );
    //         Ok(())
    //     }
    //     Err(BlockError::RepeatProposal { proposer, slot }) => {
    //         warn!(
    //             log,
    //             "Block ignored due to repeat proposal";
    //             "msg" => "this can happen when a VC uses fallback BNs. \
    //                 whilst this is not necessarily an error, it can indicate issues with a BN \
    //                 or between the VC and BN.",
    //             "slot" => slot,
    //             "proposer" => proposer,
    //         );
    //         Ok(())
    //     }
    //     Err(e) => {
    //         let msg = format!("{:?}", e);
    //         error!(
    //             log,
    //             "Invalid block provided to HTTP API";
    //             "reason" => &msg
    //         );
    //         Err(warp_utils::reject::broadcast_without_import(msg))
    //     }
    // }
    Ok(())
}
