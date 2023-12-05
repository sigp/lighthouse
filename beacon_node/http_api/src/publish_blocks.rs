use crate::metrics;

use beacon_chain::block_verification_types::{AsBlock, BlockContentsError};
use beacon_chain::validator_monitor::{get_block_delay_ms, timestamp_now};
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes, BlockError,
    IntoGossipVerifiedBlockContents, NotifyExecutionLayer,
};
use eth2::types::{BroadcastValidation, ErrorMessage};
use eth2::types::{FullPayloadContents, SignedBlockContents};
use execution_layer::ProvenancedPayload;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BeaconBlockRef, BlindedPayload, EthSpec, ExecPayload, ExecutionBlockHash,
    ForkName, FullPayload, FullPayloadMerge, Hash256, SignedBeaconBlock, SignedBlobSidecarList,
};
use warp::http::StatusCode;
use warp::{reply::Response, Rejection, Reply};

pub enum ProvenancedBlock<T: BeaconChainTypes, B: IntoGossipVerifiedBlockContents<T>> {
    /// The payload was built using a local EE.
    Local(B, PhantomData<T>),
    /// The payload was build using a remote builder (e.g., via a mev-boost
    /// compatible relay).
    Builder(B, PhantomData<T>),
}

impl<T: BeaconChainTypes, B: IntoGossipVerifiedBlockContents<T>> ProvenancedBlock<T, B> {
    pub fn local(block: B) -> Self {
        Self::Local(block, PhantomData)
    }

    pub fn builder(block: B) -> Self {
        Self::Builder(block, PhantomData)
    }
}

/// Handles a request from the HTTP API for full blocks.
pub async fn publish_block<T: BeaconChainTypes, B: IntoGossipVerifiedBlockContents<T>>(
    block_root: Option<Hash256>,
    provenanced_block: ProvenancedBlock<T, B>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
    validation_level: BroadcastValidation,
    duplicate_status_code: StatusCode,
) -> Result<Response, Rejection> {
    let seen_timestamp = timestamp_now();

    let (block_contents, is_locally_built_block) = match provenanced_block {
        ProvenancedBlock::Local(block_contents, _) => (block_contents, true),
        ProvenancedBlock::Builder(block_contents, _) => (block_contents, false),
    };
    let block = block_contents.inner_block();
    let delay = get_block_delay_ms(seen_timestamp, block.message(), &chain.slot_clock);
    debug!(log, "Signed block received in HTTP API"; "slot" => block.slot());

    /* actually publish a block */
    let publish_block = move |block: Arc<SignedBeaconBlock<T::EthSpec>>,
                              blobs_opt: Option<SignedBlobSidecarList<T::EthSpec>>,
                              sender,
                              log,
                              seen_timestamp| {
        let publish_timestamp = timestamp_now();
        let publish_delay = publish_timestamp
            .checked_sub(seen_timestamp)
            .unwrap_or_else(|| Duration::from_secs(0));

        info!(log, "Signed block published to network via HTTP API"; "slot" => block.slot(), "publish_delay" => ?publish_delay);

        match block.as_ref() {
            SignedBeaconBlock::Base(_)
            | SignedBeaconBlock::Altair(_)
            | SignedBeaconBlock::Merge(_)
            | SignedBeaconBlock::Capella(_) => {
                crate::publish_pubsub_message(&sender, PubsubMessage::BeaconBlock(block.clone()))
                    .map_err(|_| BlockError::BeaconChainError(BeaconChainError::UnableToPublish))?;
            }
            SignedBeaconBlock::Deneb(_) => {
                let mut pubsub_messages = vec![PubsubMessage::BeaconBlock(block.clone())];
                if let Some(signed_blobs) = blobs_opt {
                    for (blob_index, blob) in signed_blobs.into_iter().enumerate() {
                        pubsub_messages.push(PubsubMessage::BlobSidecar(Box::new((
                            blob_index as u64,
                            blob,
                        ))));
                    }
                }
                crate::publish_pubsub_messages(&sender, pubsub_messages)
                    .map_err(|_| BlockError::BeaconChainError(BeaconChainError::UnableToPublish))?;
            }
        };
        Ok(())
    };

    /* only publish if gossip- and consensus-valid and equivocation-free */
    let chain_clone = chain.clone();
    let slot = block.message().slot();
    let proposer_index = block.message().proposer_index();
    let sender_clone = network_tx.clone();
    let log_clone = log.clone();

    // We can clone this because the blobs are `Arc`'d in `BlockContents`, but the block is not,
    // so we avoid cloning the block at this point.
    let blobs_opt = block_contents.inner_blobs();

    /* if we can form a `GossipVerifiedBlock`, we've passed our basic gossip checks */
    let (gossip_verified_block, gossip_verified_blobs) =
        match block_contents.into_gossip_verified_block(&chain) {
            Ok(b) => b,
            Err(BlockContentsError::BlockError(BlockError::BlockIsAlreadyKnown)) => {
                // Allow the status code for duplicate blocks to be overridden based on config.
                return Ok(warp::reply::with_status(
                    warp::reply::json(&ErrorMessage {
                        code: duplicate_status_code.as_u16(),
                        message: "duplicate block".to_string(),
                        stacktraces: vec![],
                    }),
                    duplicate_status_code,
                )
                .into_response());
            }
            Err(e) => {
                warn!(
                    log,
                    "Not publishing block - not gossip verified";
                    "slot" => slot,
                    "error" => ?e
                );
                return Err(warp_utils::reject::custom_bad_request(e.to_string()));
            }
        };

    // Clone here, so we can take advantage of the `Arc`. The block in `BlockContents` is not,
    // `Arc`'d but blobs are.
    let block = gossip_verified_block.block.block_cloned();

    let block_root = block_root.unwrap_or(gossip_verified_block.block_root);

    if let BroadcastValidation::Gossip = validation_level {
        publish_block(
            block.clone(),
            blobs_opt.clone(),
            sender_clone.clone(),
            log.clone(),
            seen_timestamp,
        )
        .map_err(|_| warp_utils::reject::custom_server_error("unable to publish".into()))?;
    }

    let block_clone = block.clone();

    let publish_fn = move || match validation_level {
        BroadcastValidation::Gossip => Ok(()),
        BroadcastValidation::Consensus => publish_block(
            block_clone,
            blobs_opt,
            sender_clone,
            log_clone,
            seen_timestamp,
        ),
        BroadcastValidation::ConsensusAndEquivocation => {
            if chain_clone
                .observed_block_producers
                .read()
                .proposer_has_been_observed(block_clone.message(), block_root)
                .map_err(|e| BlockError::BeaconChainError(e.into()))?
                .is_slashable()
            {
                warn!(
                    log_clone,
                    "Not publishing equivocating block";
                    "slot" => block_clone.slot()
                );
                Err(BlockError::Slashable)
            } else {
                publish_block(
                    block_clone,
                    blobs_opt,
                    sender_clone,
                    log_clone,
                    seen_timestamp,
                )
            }
        }
    };

    if let Some(gossip_verified_blobs) = gossip_verified_blobs {
        for blob in gossip_verified_blobs {
            if let Err(e) = chain.process_gossip_blob(blob).await {
                let msg = format!("Invalid blob: {e}");
                return if let BroadcastValidation::Gossip = validation_level {
                    Err(warp_utils::reject::broadcast_without_import(msg))
                } else {
                    error!(
                        log,
                        "Invalid blob provided to HTTP API";
                        "reason" => &msg
                    );
                    Err(warp_utils::reject::custom_bad_request(msg))
                };
            }
        }
    }

    match chain
        .process_block(
            block_root,
            gossip_verified_block,
            NotifyExecutionLayer::Yes,
            publish_fn,
        )
        .await
    {
        Ok(AvailabilityProcessingStatus::Imported(root)) => {
            info!(
                log,
                "Valid block from HTTP API";
                "block_delay" => ?delay,
                "root" => format!("{}", root),
                "proposer_index" => proposer_index,
                "slot" =>slot,
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

            // Only perform late-block logging here if the block is local. For
            // blocks built with builders we consider the broadcast time to be
            // when the blinded block is published to the builder.
            if is_locally_built_block {
                late_block_logging(&chain, seen_timestamp, block.message(), root, "local", &log)
            }
            Ok(warp::reply().into_response())
        }
        Ok(AvailabilityProcessingStatus::MissingComponents(_, block_root)) => {
            let msg = format!("Missing parts of block with root {:?}", block_root);
            if let BroadcastValidation::Gossip = validation_level {
                Err(warp_utils::reject::broadcast_without_import(msg))
            } else {
                error!(
                    log,
                    "Invalid block provided to HTTP API";
                    "reason" => &msg
                );
                Err(warp_utils::reject::custom_bad_request(msg))
            }
        }
        Err(BlockError::BeaconChainError(BeaconChainError::UnableToPublish)) => {
            Err(warp_utils::reject::custom_server_error(
                "unable to publish to network channel".to_string(),
            ))
        }
        Err(BlockError::Slashable) => Err(warp_utils::reject::custom_bad_request(
            "proposal for this slot and proposer has already been seen".to_string(),
        )),
        Err(e) => {
            if let BroadcastValidation::Gossip = validation_level {
                Err(warp_utils::reject::broadcast_without_import(format!("{e}")))
            } else {
                let msg = format!("{:?}", e);
                error!(
                    log,
                    "Invalid block provided to HTTP API";
                    "reason" => &msg
                );
                Err(warp_utils::reject::custom_bad_request(format!(
                    "Invalid block: {e}"
                )))
            }
        }
    }
}

/// Handles a request from the HTTP API for blinded blocks. This converts blinded blocks into full
/// blocks before publishing.
pub async fn publish_blinded_block<T: BeaconChainTypes>(
    block_contents: SignedBlockContents<T::EthSpec, BlindedPayload<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
    validation_level: BroadcastValidation,
    duplicate_status_code: StatusCode,
) -> Result<Response, Rejection> {
    let block_root = block_contents.signed_block().canonical_root();
    let full_block: ProvenancedBlock<T, SignedBlockContents<T::EthSpec>> =
        reconstruct_block(chain.clone(), block_root, block_contents, log.clone()).await?;
    publish_block::<T, _>(
        Some(block_root),
        full_block,
        chain,
        network_tx,
        log,
        validation_level,
        duplicate_status_code,
    )
    .await
}

/// Deconstruct the given blinded block, and construct a full block. This attempts to use the
/// execution layer's payload cache, and if that misses, attempts a blind block proposal to retrieve
/// the full payload.
pub async fn reconstruct_block<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block_contents: SignedBlockContents<T::EthSpec, BlindedPayload<T::EthSpec>>,
    log: Logger,
) -> Result<ProvenancedBlock<T, SignedBlockContents<T::EthSpec>>, Rejection> {
    let block = block_contents.signed_block();
    let full_payload_opt = if let Ok(payload_header) = block.message().body().execution_payload() {
        let el = chain.execution_layer.as_ref().ok_or_else(|| {
            warp_utils::reject::custom_server_error("Missing execution layer".to_string())
        })?;

        // If the execution block hash is zero, use an empty payload.
        let full_payload_contents = if payload_header.block_hash() == ExecutionBlockHash::zero() {
            let fork_name = chain
                .spec
                .fork_name_at_epoch(block.slot().epoch(T::EthSpec::slots_per_epoch()));
            if fork_name == ForkName::Merge {
                let payload: FullPayload<T::EthSpec> = FullPayloadMerge::default().into();
                ProvenancedPayload::Local(FullPayloadContents::Payload(payload.into()))
            } else {
                Err(warp_utils::reject::custom_server_error(
                    "Failed to construct full payload - block hash must be non-zero after Bellatrix.".to_string()
                ))?
            }
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
                .propose_blinded_beacon_block(block_root, &block_contents)
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

        Some(full_payload_contents)
    } else {
        None
    };

    match full_payload_opt {
        // A block without a payload is pre-merge and we consider it locally
        // built.
        None => block_contents
            .try_into_full_block_and_blobs(None)
            .map(ProvenancedBlock::local),
        Some(ProvenancedPayload::Local(full_payload_contents)) => block_contents
            .try_into_full_block_and_blobs(Some(full_payload_contents))
            .map(ProvenancedBlock::local),
        Some(ProvenancedPayload::Builder(full_payload_contents)) => block_contents
            .try_into_full_block_and_blobs(Some(full_payload_contents))
            .map(ProvenancedBlock::builder),
    }
    .map_err(|e| {
        warp_utils::reject::custom_server_error(format!("Unable to add payload to block: {e:?}"))
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
