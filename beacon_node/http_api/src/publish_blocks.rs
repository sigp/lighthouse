use crate::metrics;
use beacon_chain::blob_verification::AsBlock;
use beacon_chain::blob_verification::BlockWrapper;
use beacon_chain::validator_monitor::{get_block_delay_ms, timestamp_now};
use beacon_chain::{AvailabilityProcessingStatus, NotifyExecutionLayer};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError, CountUnrealized};
use eth2::types::SignedBlockContents;
use execution_layer::ProvenancedPayload;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BeaconBlockRef, BlindedPayload, EthSpec, ExecPayload, ExecutionBlockHash,
    FullPayload, Hash256, SignedBeaconBlock,
};
use warp::Rejection;

pub enum ProvenancedBlock<T: EthSpec> {
    /// The payload was built using a local EE.
    Local(SignedBlockContents<T, FullPayload<T>>),
    /// The payload was build using a remote builder (e.g., via a mev-boost
    /// compatible relay).
    Builder(SignedBlockContents<T, FullPayload<T>>),
}

/// Handles a request from the HTTP API for full blocks.
pub async fn publish_block<T: BeaconChainTypes>(
    block_root: Option<Hash256>,
    provenanced_block: ProvenancedBlock<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
) -> Result<(), Rejection> {
    let seen_timestamp = timestamp_now();
    let (block, maybe_blobs, is_locally_built_block) = match provenanced_block {
        ProvenancedBlock::Local(block_contents) => {
            let (block, maybe_blobs) = block_contents.deconstruct();
            (Arc::new(block), maybe_blobs, true)
        }
        ProvenancedBlock::Builder(block_contents) => {
            let (block, maybe_blobs) = block_contents.deconstruct();
            (Arc::new(block), maybe_blobs, false)
        }
    };
    let delay = get_block_delay_ms(seen_timestamp, block.message(), &chain.slot_clock);

    //FIXME(sean) have to move this to prior to publishing because it's included in the blobs sidecar message.
    //this may skew metrics
    let block_root = block_root.unwrap_or_else(|| block.canonical_root());
    debug!(
        log,
        "Signed block published to HTTP API";
        "slot" => block.slot()
    );

    // Send the block, regardless of whether or not it is valid. The API
    // specification is very clear that this is the desired behaviour.
    let wrapped_block: BlockWrapper<T::EthSpec> = match block.as_ref() {
        SignedBeaconBlock::Base(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Merge(_)
        | SignedBeaconBlock::Capella(_) => {
            crate::publish_pubsub_message(network_tx, PubsubMessage::BeaconBlock(block.clone()))?;
            block.into()
        }
        SignedBeaconBlock::Eip4844(_) => {
            crate::publish_pubsub_message(network_tx, PubsubMessage::BeaconBlock(block.clone()))?;
            if let Some(blobs) = maybe_blobs {
                for (blob_index, blob) in blobs.into_iter().enumerate() {
                    crate::publish_pubsub_message(
                        network_tx,
                        PubsubMessage::BlobSidecar(Box::new((blob_index as u64, blob))),
                    )?;
                }
            }
            block.into()
        }
    };
    // Determine the delay after the start of the slot, register it with metrics.

    let available_block = match wrapped_block
        .clone()
        .into_available_block(chain.kzg.clone(), |epoch| chain.block_needs_da_check(epoch))
    {
        Some(available_block) => available_block,
        None => {
            error!(
                log,
                "Invalid block provided to HTTP API unavailable block"; //TODO(sean) probably want a real error here
            );
            return Err(warp_utils::reject::broadcast_without_import(
                "unavailable block".to_string(),
            ));
        }
    };

    match chain
        .process_block(
            block_root,
            wrapped_block,
            CountUnrealized::True,
            NotifyExecutionLayer::Yes,
        )
        .await
    {
        Ok(AvailabilityProcessingStatus::Imported(root)) => {
            info!(
                log,
                "Valid block from HTTP API";
                "block_delay" => ?delay,
                "root" => format!("{}", root),
                "proposer_index" => available_block.message().proposer_index(),
                "slot" => available_block.slot(),
            );

            // Notify the validator monitor.
            chain.validator_monitor.read().register_api_block(
                seen_timestamp,
                available_block.message(),
                root,
                &chain.slot_clock,
            );

            // Update the head since it's likely this block will become the new
            // head.
            chain.recompute_head_at_current_slot().await;

            // Only perform late-block logging here if the block is local. For
            // blocks built with builders we consider the broadcast time to be
            // when the blinded block is published to the builder.
            if is_locally_built_block {
                late_block_logging(
                    &chain,
                    seen_timestamp,
                    available_block.message(),
                    root,
                    "local",
                    &log,
                )
            }

            Ok(())
        }
        Ok(AvailabilityProcessingStatus::PendingBlock(block_root)) => {
            let msg = format!("Missing block with root {:?}", block_root);
            error!(
                log,
                "Invalid block provided to HTTP API";
                "reason" => &msg
            );
            Err(warp_utils::reject::broadcast_without_import(msg))
        }
        Ok(AvailabilityProcessingStatus::PendingBlobs(blob_ids)) => {
            let msg = format!("Missing blobs {:?}", blob_ids);
            error!(
                log,
                "Invalid block provided to HTTP API";
                "reason" => &msg
            );
            Err(warp_utils::reject::broadcast_without_import(msg))
        }
        Err(BlockError::BlockIsAlreadyKnown) => {
            info!(
                log,
                "Block from HTTP API already known";
                "block" => ?block_root,
                "slot" => available_block.slot(),
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
    publish_block::<T>(Some(block_root), full_block, chain, network_tx, log).await
}

/// Deconstruct the given blinded block, and construct a full block. This attempts to use the
/// execution layer's payload cache, and if that misses, attempts a blind block proposal to retrieve
/// the full payload.
async fn reconstruct_block<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block: SignedBeaconBlock<T::EthSpec, BlindedPayload<T::EthSpec>>,
    log: Logger,
) -> Result<ProvenancedBlock<T::EthSpec>, Rejection> {
    let full_payload_opt = if let Ok(payload_header) = block.message().body().execution_payload() {
        let el = chain.execution_layer.as_ref().ok_or_else(|| {
            warp_utils::reject::custom_server_error("Missing execution layer".to_string())
        })?;

        // If the execution block hash is zero, use an empty payload.
        let full_payload = if payload_header.block_hash() == ExecutionBlockHash::zero() {
            let payload = FullPayload::default_at_fork(
                chain
                    .spec
                    .fork_name_at_epoch(block.slot().epoch(T::EthSpec::slots_per_epoch())),
            )
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "Default payload construction error: {e:?}"
                ))
            })?
            .into();
            ProvenancedPayload::Local(payload)
        // If we already have an execution payload with this transactions root cached, use it.
        } else if let Some(cached_payload) =
            el.get_payload_by_root(&payload_header.tree_hash_root())
        {
            info!(log, "Reconstructing a full block using a local payload"; "block_hash" => ?cached_payload.block_hash());
            ProvenancedPayload::Local(cached_payload)
        // Otherwise, this means we are attempting a blind block proposal.
        } else {
            // Perform the logging for late blocks when we publish to the
            // builder, rather than when we publish to the network. This helps
            // prevent false positive logs when the builder publishes to the P2P
            // network significantly earlier than when they return the block to
            // us.
            late_block_logging(
                &chain,
                timestamp_now(),
                block.message(),
                block_root,
                "builder",
                &log,
            );

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
            ProvenancedPayload::Builder(full_payload)
        };

        Some(full_payload)
    } else {
        None
    };

    match full_payload_opt {
        // A block without a payload is pre-merge and we consider it locally
        // built.
        None => block
            .try_into_full_block(None)
            .map(SignedBlockContents::Block)
            .map(ProvenancedBlock::Local),
        Some(ProvenancedPayload::Local(full_payload)) => block
            .try_into_full_block(Some(full_payload))
            .map(SignedBlockContents::Block)
            .map(ProvenancedBlock::Local),
        Some(ProvenancedPayload::Builder(full_payload)) => block
            .try_into_full_block(Some(full_payload))
            .map(SignedBlockContents::Block)
            .map(ProvenancedBlock::Builder),
    }
    .ok_or_else(|| {
        warp_utils::reject::custom_server_error("Unable to add payload to block".to_string())
    })
}

/// If the `seen_timestamp` is some time after the start of the slot for
/// `block`, create some logs to indicate that the block was published late.
fn late_block_logging<T: BeaconChainTypes, P: AbstractExecPayload<T::EthSpec>>(
    chain: &BeaconChain<T>,
    seen_timestamp: Duration,
    block: BeaconBlockRef<T::EthSpec, P>,
    root: Hash256,
    provenance: &str,
    log: &Logger,
) {
    let delay = get_block_delay_ms(seen_timestamp, block, &chain.slot_clock);

    metrics::observe_timer_vec(
        &metrics::HTTP_API_BLOCK_BROADCAST_DELAY_TIMES,
        &[provenance],
        delay,
    );

    // Perform some logging to inform users if their blocks are being produced
    // late.
    //
    // Check to see the thresholds are non-zero to avoid logging errors with small
    // slot times (e.g., during testing)
    let too_late_threshold = chain.slot_clock.unagg_attestation_production_delay();
    let delayed_threshold = too_late_threshold / 2;
    if delay >= too_late_threshold {
        error!(
            log,
            "Block was broadcast too late";
            "msg" => "system may be overloaded, block likely to be orphaned",
            "provenance" => provenance,
            "delay_ms" => delay.as_millis(),
            "slot" => block.slot(),
            "root" => ?root,
        )
    } else if delay >= delayed_threshold {
        error!(
            log,
            "Block broadcast was delayed";
            "msg" => "system may be overloaded, block may be orphaned",
            "provenance" => provenance,
            "delay_ms" => delay.as_millis(),
            "slot" => block.slot(),
            "root" => ?root,
        )
    }
}
