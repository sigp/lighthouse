use crate::metrics;

use beacon_chain::blob_verification::{GossipBlobError, GossipVerifiedBlob};
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::validator_monitor::{get_block_delay_ms, timestamp_now};
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes, BlockError,
    GossipVerifiedBlock, NotifyExecutionLayer, YetAnotherBlockType,
};
use eth2::types::{BlobsBundle, BroadcastValidation, PublishBlockRequest, SignedBlockContents};
use eth2::types::{ExecutionPayloadAndBlobs, FullPayloadContents};
use execution_layer::ProvenancedPayload;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BeaconBlockRef, BlobSidecar, EthSpec, ExecPayload, ExecutionBlockHash,
    ForkName, FullPayload, FullPayloadMerge, Hash256, SignedBeaconBlock, SignedBlindedBeaconBlock,
};
use warp::http::StatusCode;
use warp::{reply::Response, Rejection, Reply};

pub enum ProvenancedBlock<T: BeaconChainTypes> {
    /// The payload was built using a local EE.
    Local(YetAnotherBlockType<T>),
    /// The payload was build using a remote builder (e.g., via a mev-boost
    /// compatible relay).
    Builder(YetAnotherBlockType<T>),
}

impl<T: BeaconChainTypes> ProvenancedBlock<T> {
    pub fn local(contents: YetAnotherBlockType<T>) -> Self {
        Self::Local(contents)
    }

    pub fn local_from_publish_request(request: PublishBlockRequest<T::EthSpec>) -> Self {
        match request {
            PublishBlockRequest::Block(block) => Self::Local((block, vec![])),
            PublishBlockRequest::BlockContents(block_contents) => {
                let SignedBlockContents {
                    signed_block,
                    kzg_proofs,
                    blobs,
                } = block_contents;
                let blobs = blobs.into_iter().zip(kzg_proofs).collect::<Vec<_>>();
                Self::Local((signed_block, blobs))
            }
        }
    }

    pub fn builder(contents: YetAnotherBlockType<T>) -> Self {
        Self::Builder(contents)
    }
}

/// Handles a request from the HTTP API for full blocks.
pub async fn publish_block<T: BeaconChainTypes>(
    block_root: Option<Hash256>,
    provenanced_block: ProvenancedBlock<T>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
    validation_level: BroadcastValidation,
    // FIXME(sproul): restore duplicate status code
    _duplicate_status_code: StatusCode,
) -> Result<Response, Rejection> {
    let seen_timestamp = timestamp_now();

    let ((unverified_block, unverified_blobs), is_locally_built_block) = match provenanced_block {
        ProvenancedBlock::Local(contents) => (contents, true),
        ProvenancedBlock::Builder(contents) => (contents, false),
    };
    let block = unverified_block.clone();
    let delay = get_block_delay_ms(seen_timestamp, block.message(), &chain.slot_clock);
    debug!(log, "Signed block received in HTTP API"; "slot" => block.slot());

    /* actually publish a block */
    let publish_block = move |block: Arc<SignedBeaconBlock<T::EthSpec>>,
                              should_publish: bool,
                              blob_sidecars: Vec<Arc<BlobSidecar<T::EthSpec>>>,
                              sender,
                              log,
                              seen_timestamp|
          -> Result<(), BlockError<T::EthSpec>> {
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
                crate::publish_pubsub_message(&sender, PubsubMessage::BeaconBlock(block))
                    .map_err(|_| BlockError::BeaconChainError(BeaconChainError::UnableToPublish))?;
            }
            SignedBeaconBlock::Deneb(_) | SignedBeaconBlock::Electra(_) => {
                let mut pubsub_messages = if should_publish {
                    vec![PubsubMessage::BeaconBlock(block)]
                } else {
                    vec![]
                };
                for blob in blob_sidecars.into_iter() {
                    pubsub_messages.push(PubsubMessage::BlobSidecar(Box::new((blob.index, blob))));
                }
                crate::publish_pubsub_messages(&sender, pubsub_messages)
                    .map_err(|_| BlockError::BeaconChainError(BeaconChainError::UnableToPublish))?;
            }
        };
        Ok(())
    };

    /* only publish if gossip- and consensus-valid and equivocation-free */
    let slot = block.message().slot();
    let proposer_index = block.message().proposer_index();
    let sender_clone = network_tx.clone();

    // Check blob inclusion proofs and convert to blob sidecars ready for publication.
    let mut blob_sidecars = unverified_blobs
        .into_iter()
        .enumerate()
        .map(|(i, (unverified_blob, proof))| {
            //TODO(sean) restore metric
            // let _timer = metrics::start_timer(&metrics::BLOB_SIDECAR_INCLUSION_PROOF_COMPUTATION);
            let blob_sidecar = BlobSidecar::new(i, unverified_blob, &block, proof).map(Arc::new);
            blob_sidecar.map_err(|e| {
                error!(
                    log,
                    "Invalid blob - not publishing block";
                    "error" => ?e,
                    "blob_index" => i,
                    "slot" => slot,
                );
                warp_utils::reject::custom_bad_request(format!("{e:?}"))
            })
        })
        .collect::<Result<Vec<_>, Rejection>>()?;

    // Gossip verify the block and blobs separately.
    let gossip_verified_block_result = GossipVerifiedBlock::new(unverified_block, &chain);
    let gossip_verified_blobs = blob_sidecars
        .iter_mut()
        .map(|blob_sidecar| {
            let gossip_verified_blob =
                GossipVerifiedBlob::new(blob_sidecar.clone(), blob_sidecar.index, &chain);

            match gossip_verified_blob {
                Ok(blob) => Ok(Some(blob)),
                Err(GossipBlobError::RepeatBlob { proposer, .. }) => {
                    // Log the error but do not abort publication, we may need to publish the block
                    // or some of the other blobs if the block & blobs are only partially published
                    // by the other publisher.
                    debug!(
                        log,
                        "Blob for publication already known";
                        "blob_index" => blob_sidecar.index,
                        "slot" => slot,
                        "proposer" => proposer,
                    );
                    Ok(None)
                }
                Err(e) => {
                    error!(
                        log,
                        "Blob for publication is gossip-invalid";
                        "blob_index" => blob_sidecar.index,
                        "slot" => slot,
                        "error" => ?e,
                    );
                    Err(warp_utils::reject::custom_bad_request(e.to_string()))
                }
            }
        })
        .collect::<Result<Vec<_>, Rejection>>()?;

    let publishable_blobs = gossip_verified_blobs
        .iter()
        .flatten()
        .map(|b| b.clone_blob())
        .collect::<Vec<_>>();

    let block_root = block_root.unwrap_or_else(|| {
        gossip_verified_block_result.as_ref().map_or_else(
            |_| block.canonical_root(),
            |verified_block| verified_block.block_root,
        )
    });

    let should_publish_block = gossip_verified_block_result.is_ok();
    if let BroadcastValidation::Gossip = validation_level {
        publish_block(
            block.clone(),
            should_publish_block,
            publishable_blobs.clone(),
            sender_clone.clone(),
            log.clone(),
            seen_timestamp,
        )
        .map_err(|_| warp_utils::reject::custom_server_error("unable to publish".into()))?;
    }

    let published = Arc::new(AtomicBool::new(false));
    let publish_fn = || {
        match validation_level {
            BroadcastValidation::Gossip => (),
            BroadcastValidation::Consensus => publish_block(
                block.clone(),
                should_publish_block,
                publishable_blobs.clone(),
                sender_clone.clone(),
                log.clone(),
                seen_timestamp,
            )?,
            BroadcastValidation::ConsensusAndEquivocation => {
                check_slashable(&chain, block_root, &block, &log)?;
                publish_block(
                    block.clone(),
                    should_publish_block,
                    publishable_blobs.clone(),
                    sender_clone.clone(),
                    log.clone(),
                    seen_timestamp,
                )?;
            }
        };
        published.store(true, Ordering::SeqCst);
        Ok(())
    };

    for blob in gossip_verified_blobs.into_iter().flatten() {
        // Importing the blobs could trigger block import and network publication in the case
        // where the block was already seen on gossip.
        if let Err(e) = Box::pin(chain.process_gossip_blob(blob, &publish_fn)).await {
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

    let gossip_verified_block = match gossip_verified_block_result {
        Ok(block) => block,
        Err(BlockError::BlockIsAlreadyKnown(..)) => {
            if published.load(Ordering::SeqCst) {
                // Block was a dupicate on gossip, but we still published some blobs, and
                // if broadcast_validation is equal to consensus or consensus_and_equivocation
                // then those checks passed too.
                return Err(warp_utils::reject::broadcast_without_import(
                    "block published but already partly known".to_string(),
                ));
            } else {
                // We don't know what was invalid here.
                return Err(warp_utils::reject::custom_bad_request(
                    "block not valid - see logs for details".to_string(),
                ));
            }
        }
        Err(e) => {
            warn!(
                log,
                "Not publishing block - not gossip verified";
                "slot" => slot,
                "error" => %e
            );
            return Err(warp_utils::reject::custom_bad_request(e.to_string()));
        }
    };

    match Box::pin(chain.process_block(
        block_root,
        gossip_verified_block,
        NotifyExecutionLayer::Yes,
        publish_fn,
    ))
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
    blinded_block: Arc<SignedBlindedBeaconBlock<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
    validation_level: BroadcastValidation,
    duplicate_status_code: StatusCode,
) -> Result<Response, Rejection> {
    let block_root = blinded_block.canonical_root();
    let full_block =
        reconstruct_block(chain.clone(), block_root, blinded_block, log.clone()).await?;
    publish_block::<T>(
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
    block: Arc<SignedBlindedBeaconBlock<T::EthSpec>>,
    log: Logger,
) -> Result<ProvenancedBlock<T>, Rejection> {
    let full_payload_opt = if let Ok(payload_header) = block.message().body().execution_payload() {
        let el = chain.execution_layer.as_ref().ok_or_else(|| {
            warp_utils::reject::custom_server_error("Missing execution layer".to_string())
        })?;

        // If the execution block hash is zero, use an empty payload.
        let full_payload_contents = if payload_header.block_hash() == ExecutionBlockHash::zero() {
            let fork_name = chain.spec.fork_name_at_epoch(
                block
                    .slot()
                    .epoch(<<T as BeaconChainTypes>::EthSpec as EthSpec>::slots_per_epoch()),
            );
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

        Some(full_payload_contents)
    } else {
        None
    };

    // Perf: cloning the block here to unblind it is a little sub-optimal. This is considered an
    // acceptable tradeoff to avoid passing blocks around on the stack (unarced), which blows up
    // the size of futures.
    let block = (*block).clone();
    match full_payload_opt {
        // A block without a payload is pre-merge and we consider it locally
        // built.
        None => block
            .try_into_full_block(None)
            .ok_or("Failed to build full block with payload".to_string())
            .map(|full_block| ProvenancedBlock::local((Arc::new(full_block), vec![]))),
        Some(ProvenancedPayload::Local(full_payload_contents)) => {
            into_full_block_and_blobs::<T>(block, full_payload_contents)
                .map(ProvenancedBlock::local)
        }
        Some(ProvenancedPayload::Builder(full_payload_contents)) => {
            into_full_block_and_blobs::<T>(block, full_payload_contents)
                .map(ProvenancedBlock::builder)
        }
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

/// Check if any of the blobs or the block are slashable. Returns `BlockError::Slashable` if so.
fn check_slashable<T: BeaconChainTypes>(
    chain_clone: &BeaconChain<T>,
    block_root: Hash256,
    block_clone: &SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
    log_clone: &Logger,
) -> Result<(), BlockError<T::EthSpec>> {
    let slashable_cache = chain_clone.observed_slashable.read();
    if slashable_cache
        .is_slashable(
            block_clone.slot(),
            block_clone.message().proposer_index(),
            block_root,
        )
        .map_err(|e| BlockError::BeaconChainError(e.into()))?
    {
        warn!(
            log_clone,
            "Not publishing equivocating block";
            "slot" => block_clone.slot()
        );
        return Err(BlockError::Slashable);
    }
    Ok(())
}

/// Converting from a `SignedBlindedBeaconBlock` into a full `SignedBlockContents`.
pub fn into_full_block_and_blobs<T: BeaconChainTypes>(
    blinded_block: SignedBlindedBeaconBlock<T::EthSpec>,
    maybe_full_payload_contents: FullPayloadContents<T::EthSpec>,
) -> Result<YetAnotherBlockType<T>, String> {
    match maybe_full_payload_contents {
        // This variant implies a pre-deneb block
        FullPayloadContents::Payload(execution_payload) => {
            let signed_block = blinded_block
                .try_into_full_block(Some(execution_payload))
                .ok_or("Failed to build full block with payload".to_string())?;
            Ok((Arc::new(signed_block), vec![]))
        }
        // This variant implies a post-deneb block
        FullPayloadContents::PayloadAndBlobs(payload_and_blobs) => {
            let ExecutionPayloadAndBlobs {
                execution_payload,
                blobs_bundle,
            } = payload_and_blobs;
            let signed_block = blinded_block
                .try_into_full_block(Some(execution_payload))
                .ok_or("Failed to build full block with payload".to_string())?;

            let BlobsBundle {
                commitments: _,
                proofs,
                blobs,
            } = blobs_bundle;
            let blob_contents = proofs
                .into_iter()
                .zip(blobs)
                .map(|(proof, blob)| (blob, proof))
                .collect::<Vec<_>>();

            Ok((Arc::new(signed_block), blob_contents))
        }
    }
}
