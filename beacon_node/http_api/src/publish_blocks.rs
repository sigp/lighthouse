use crate::metrics;
use std::future::Future;

use beacon_chain::blob_verification::{GossipBlobError, GossipVerifiedBlob};
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::data_column_verification::{GossipDataColumnError, GossipVerifiedDataColumn};
use beacon_chain::validator_monitor::{get_block_delay_ms, timestamp_now};
use beacon_chain::{
    build_blob_data_column_sidecars, AvailabilityProcessingStatus, BeaconChain, BeaconChainError,
    BeaconChainTypes, BlockError, IntoGossipVerifiedBlock, NotifyExecutionLayer,
};
use eth2::types::{
    BlobsBundle, BroadcastValidation, ErrorMessage, ExecutionPayloadAndBlobs, FullPayloadContents,
    PublishBlockRequest, SignedBlockContents,
};
use execution_layer::ProvenancedPayload;
use futures::TryFutureExt;
use lighthouse_network::{NetworkGlobals, PubsubMessage};
use network::NetworkMessage;
use rand::prelude::SliceRandom;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BeaconBlockRef, BlobSidecar, BlobsList, BlockImportSource,
    DataColumnSubnetId, EthSpec, ExecPayload, ExecutionBlockHash, ForkName, FullPayload,
    FullPayloadBellatrix, Hash256, KzgProofs, SignedBeaconBlock, SignedBlindedBeaconBlock,
};
use warp::http::StatusCode;
use warp::{reply::Response, Rejection, Reply};

pub type UnverifiedBlobs<T> = Option<(
    KzgProofs<<T as BeaconChainTypes>::EthSpec>,
    BlobsList<<T as BeaconChainTypes>::EthSpec>,
)>;

pub enum ProvenancedBlock<T: BeaconChainTypes, B: IntoGossipVerifiedBlock<T>> {
    /// The payload was built using a local EE.
    Local(B, UnverifiedBlobs<T>, PhantomData<T>),
    /// The payload was build using a remote builder (e.g., via a mev-boost
    /// compatible relay).
    Builder(B, UnverifiedBlobs<T>, PhantomData<T>),
}

impl<T: BeaconChainTypes, B: IntoGossipVerifiedBlock<T>> ProvenancedBlock<T, B> {
    pub fn local(block: B, blobs: UnverifiedBlobs<T>) -> Self {
        Self::Local(block, blobs, PhantomData)
    }

    pub fn builder(block: B, blobs: UnverifiedBlobs<T>) -> Self {
        Self::Builder(block, blobs, PhantomData)
    }
}

impl<T: BeaconChainTypes> ProvenancedBlock<T, Arc<SignedBeaconBlock<T::EthSpec>>> {
    pub fn local_from_publish_request(request: PublishBlockRequest<T::EthSpec>) -> Self {
        match request {
            PublishBlockRequest::Block(block) => Self::local(block, None),
            PublishBlockRequest::BlockContents(block_contents) => {
                let SignedBlockContents {
                    signed_block,
                    kzg_proofs,
                    blobs,
                } = block_contents;
                Self::local(signed_block, Some((kzg_proofs, blobs)))
            }
        }
    }
}

/// Handles a request from the HTTP API for full blocks.
#[allow(clippy::too_many_arguments)]
pub async fn publish_block<T: BeaconChainTypes, B: IntoGossipVerifiedBlock<T>>(
    block_root: Option<Hash256>,
    provenanced_block: ProvenancedBlock<T, B>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
    validation_level: BroadcastValidation,
    duplicate_status_code: StatusCode,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
) -> Result<Response, Rejection> {
    let seen_timestamp = timestamp_now();

    let (unverified_block, unverified_blobs, is_locally_built_block) = match provenanced_block {
        ProvenancedBlock::Local(block, blobs, _) => (block, blobs, true),
        ProvenancedBlock::Builder(block, blobs, _) => (block, blobs, false),
    };
    let provenance = if is_locally_built_block {
        "local"
    } else {
        "builder"
    };
    let block = unverified_block.inner_block();
    debug!(log, "Signed block received in HTTP API"; "slot" => block.slot());

    /* actually publish a block */
    let publish_block_p2p = move |block: Arc<SignedBeaconBlock<T::EthSpec>>,
                                  sender,
                                  log,
                                  seen_timestamp|
          -> Result<(), BlockError> {
        let publish_timestamp = timestamp_now();
        let publish_delay = publish_timestamp
            .checked_sub(seen_timestamp)
            .unwrap_or_else(|| Duration::from_secs(0));

        metrics::observe_timer_vec(
            &metrics::HTTP_API_BLOCK_GOSSIP_TIMES,
            &[provenance],
            publish_delay,
        );

        info!(
            log,
            "Signed block published to network via HTTP API";
            "slot" => block.slot(),
            "publish_delay_ms" => publish_delay.as_millis(),
        );

        crate::publish_pubsub_message(&sender, PubsubMessage::BeaconBlock(block.clone()))
            .map_err(|_| BlockError::BeaconChainError(BeaconChainError::UnableToPublish))?;

        Ok(())
    };

    /* only publish if gossip- and consensus-valid and equivocation-free */
    let slot = block.message().slot();
    let sender_clone = network_tx.clone();

    let build_sidecar_task_handle =
        spawn_build_data_sidecar_task(chain.clone(), block.clone(), unverified_blobs, log.clone())?;

    // Gossip verify the block and blobs/data columns separately.
    let gossip_verified_block_result = unverified_block.into_gossip_verified_block(&chain);
    let block_root = block_root.unwrap_or_else(|| {
        gossip_verified_block_result.as_ref().map_or_else(
            |_| block.canonical_root(),
            |verified_block| verified_block.block_root,
        )
    });

    let should_publish_block = gossip_verified_block_result.is_ok();
    if BroadcastValidation::Gossip == validation_level && should_publish_block {
        publish_block_p2p(
            block.clone(),
            sender_clone.clone(),
            log.clone(),
            seen_timestamp,
        )
        .map_err(|_| warp_utils::reject::custom_server_error("unable to publish".into()))?;
    }

    let publish_fn_completed = Arc::new(AtomicBool::new(false));
    let block_to_publish = block.clone();
    let publish_fn = || {
        if should_publish_block {
            match validation_level {
                BroadcastValidation::Gossip => (),
                BroadcastValidation::Consensus => publish_block_p2p(
                    block_to_publish.clone(),
                    sender_clone.clone(),
                    log.clone(),
                    seen_timestamp,
                )?,
                BroadcastValidation::ConsensusAndEquivocation => {
                    check_slashable(&chain, block_root, &block_to_publish, &log)?;
                    publish_block_p2p(
                        block_to_publish.clone(),
                        sender_clone.clone(),
                        log.clone(),
                        seen_timestamp,
                    )?;
                }
            };
        }

        publish_fn_completed.store(true, Ordering::SeqCst);
        Ok(())
    };

    // Wait for blobs/columns to get gossip verified before proceeding further as we need them for import.
    let (gossip_verified_blobs, gossip_verified_columns) = build_sidecar_task_handle.await?;

    for blob in gossip_verified_blobs.into_iter().flatten() {
        publish_blob_sidecars(network_tx, &blob).map_err(|_| {
            warp_utils::reject::custom_server_error("unable to publish blob sidecars".into())
        })?;
        if let Err(e) = Box::pin(chain.process_gossip_blob(blob)).await {
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

    if gossip_verified_columns.iter().map(Option::is_some).count() > 0 {
        publish_column_sidecars(network_tx, &gossip_verified_columns, &chain).map_err(|_| {
            warp_utils::reject::custom_server_error("unable to publish data column sidecars".into())
        })?;
        let sampling_columns_indices = &network_globals.sampling_columns;
        let sampling_columns = gossip_verified_columns
            .into_iter()
            .flatten()
            .filter(|data_column| sampling_columns_indices.contains(&data_column.index()))
            .collect();

        // Importing the columns could trigger block import and network publication in the case
        // where the block was already seen on gossip.
        if let Err(e) =
            Box::pin(chain.process_gossip_data_columns(sampling_columns, publish_fn)).await
        {
            let msg = format!("Invalid data column: {e}");
            return if let BroadcastValidation::Gossip = validation_level {
                Err(warp_utils::reject::broadcast_without_import(msg))
            } else {
                error!(
                    log,
                    "Invalid data column during block publication";
                    "reason" => &msg
                );
                Err(warp_utils::reject::custom_bad_request(msg))
            };
        }
    }

    match gossip_verified_block_result {
        Ok(gossip_verified_block) => {
            let import_result = Box::pin(chain.process_block(
                block_root,
                gossip_verified_block,
                NotifyExecutionLayer::Yes,
                BlockImportSource::HttpApi,
                publish_fn,
            ))
            .await;
            post_block_import_logging_and_response(
                import_result,
                validation_level,
                block,
                is_locally_built_block,
                seen_timestamp,
                &chain,
                &log,
            )
            .await
        }
        Err(BlockError::DuplicateFullyImported(root)) => {
            if publish_fn_completed.load(Ordering::SeqCst) {
                post_block_import_logging_and_response(
                    Ok(AvailabilityProcessingStatus::Imported(root)),
                    validation_level,
                    block,
                    is_locally_built_block,
                    seen_timestamp,
                    &chain,
                    &log,
                )
                .await
            } else {
                // None of the components provided in this HTTP request were new, so this was an
                // entirely redundant duplicate request. Return a status code indicating this,
                // which can be overridden based on config.
                Ok(warp::reply::with_status(
                    warp::reply::json(&ErrorMessage {
                        code: duplicate_status_code.as_u16(),
                        message: "duplicate block".to_string(),
                        stacktraces: vec![],
                    }),
                    duplicate_status_code,
                )
                .into_response())
            }
        }
        Err(BlockError::DuplicateImportStatusUnknown(root)) => {
            debug!(
                log,
                "Block previously seen";
                "block_root" => ?root,
                "slot" => block.slot(),
            );
            let import_result = Box::pin(chain.process_block(
                block_root,
                block.clone(),
                NotifyExecutionLayer::Yes,
                BlockImportSource::HttpApi,
                publish_fn,
            ))
            .await;
            post_block_import_logging_and_response(
                import_result,
                validation_level,
                block,
                is_locally_built_block,
                seen_timestamp,
                &chain,
                &log,
            )
            .await
        }
        Err(e) => {
            warn!(
                log,
                "Not publishing block - not gossip verified";
                "slot" => slot,
                "error" => %e
            );
            Err(warp_utils::reject::custom_bad_request(e.to_string()))
        }
    }
}

type BuildDataSidecarTaskResult<T> = Result<
    (
        Vec<Option<GossipVerifiedBlob<T>>>,
        Vec<Option<GossipVerifiedDataColumn<T>>>,
    ),
    Rejection,
>;

/// Convert blobs to either:
///
/// 1. Blob sidecars if prior to peer DAS, or
/// 2. Data column sidecars if post peer DAS.
fn spawn_build_data_sidecar_task<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    proofs_and_blobs: UnverifiedBlobs<T>,
    log: Logger,
) -> Result<impl Future<Output = BuildDataSidecarTaskResult<T>>, Rejection> {
    chain
        .clone()
        .task_executor
        .spawn_blocking_handle(
            move || {
                let Some((kzg_proofs, blobs)) = proofs_and_blobs else {
                    return Ok((vec![], vec![]));
                };

                let peer_das_enabled = chain.spec.is_peer_das_enabled_for_epoch(block.epoch());
                if !peer_das_enabled {
                    // Pre-PeerDAS: construct blob sidecars for the network.
                    let gossip_verified_blobs =
                        build_gossip_verified_blobs(&chain, &block, blobs, kzg_proofs, &log)?;
                    Ok((gossip_verified_blobs, vec![]))
                } else {
                    // Post PeerDAS: construct data columns.
                    let gossip_verified_data_columns =
                        build_gossip_verified_data_columns(&chain, &block, blobs, &log)?;
                    Ok((vec![], gossip_verified_data_columns))
                }
            },
            "build_data_sidecars",
        )
        .ok_or(warp_utils::reject::custom_server_error(
            "runtime shutdown".to_string(),
        ))
        .map(|r| {
            r.map_err(|_| warp_utils::reject::custom_server_error("join error".to_string()))
                .and_then(|output| async move { output })
        })
}

fn build_gossip_verified_data_columns<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    block: &SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
    blobs: BlobsList<T::EthSpec>,
    log: &Logger,
) -> Result<Vec<Option<GossipVerifiedDataColumn<T>>>, Rejection> {
    let slot = block.slot();
    let data_column_sidecars =
        build_blob_data_column_sidecars(chain, block, blobs).map_err(|e| {
            error!(
                log,
                "Invalid data column - not publishing block";
                "error" => ?e,
                "slot" => slot
            );
            warp_utils::reject::custom_bad_request(format!("{e:?}"))
        })?;

    let slot = block.slot();
    let gossip_verified_data_columns = data_column_sidecars
        .into_iter()
        .map(|data_column_sidecar| {
            let column_index = data_column_sidecar.index as usize;
            let subnet =
                DataColumnSubnetId::from_column_index::<T::EthSpec>(column_index, &chain.spec);
            let gossip_verified_column =
                GossipVerifiedDataColumn::new(data_column_sidecar, subnet.into(), chain);

            match gossip_verified_column {
                Ok(blob) => Ok(Some(blob)),
                Err(GossipDataColumnError::PriorKnown { proposer, .. }) => {
                    // Log the error but do not abort publication, we may need to publish the block
                    // or some of the other data columns if the block & data columns are only
                    // partially published by the other publisher.
                    debug!(
                        log,
                        "Data column for publication already known";
                        "column_index" => column_index,
                        "slot" => slot,
                        "proposer" => proposer,
                    );
                    Ok(None)
                }
                Err(e) => {
                    error!(
                        log,
                        "Data column for publication is gossip-invalid";
                        "column_index" => column_index,
                        "slot" => slot,
                        "error" => ?e,
                    );
                    Err(warp_utils::reject::custom_bad_request(format!("{e:?}")))
                }
            }
        })
        .collect::<Result<Vec<_>, Rejection>>()?;

    Ok(gossip_verified_data_columns)
}

fn build_gossip_verified_blobs<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    block: &SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
    blobs: BlobsList<T::EthSpec>,
    kzg_proofs: KzgProofs<T::EthSpec>,
    log: &Logger,
) -> Result<Vec<Option<GossipVerifiedBlob<T>>>, Rejection> {
    let slot = block.slot();
    let gossip_verified_blobs = kzg_proofs
        .into_iter()
        .zip(blobs)
        .enumerate()
        .map(|(i, (proof, unverified_blob))| {
            let timer = metrics::start_timer(
                &beacon_chain::metrics::BLOB_SIDECAR_INCLUSION_PROOF_COMPUTATION,
            );
            let blob_sidecar = BlobSidecar::new(i, unverified_blob, block, proof)
                .map(Arc::new)
                .map_err(|e| {
                    error!(
                        log,
                        "Invalid blob - not publishing block";
                        "error" => ?e,
                        "blob_index" => i,
                        "slot" => slot,
                    );
                    warp_utils::reject::custom_bad_request(format!("{e:?}"))
                })?;
            drop(timer);

            let gossip_verified_blob =
                GossipVerifiedBlob::new(blob_sidecar.clone(), blob_sidecar.index, chain);

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

    Ok(gossip_verified_blobs)
}

fn publish_column_sidecars<T: BeaconChainTypes>(
    sender_clone: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    data_column_sidecars: &[Option<GossipVerifiedDataColumn<T>>],
    chain: &BeaconChain<T>,
) -> Result<(), BlockError> {
    let malicious_withhold_count = chain.config.malicious_withhold_count;
    let mut data_column_sidecars = data_column_sidecars
        .iter()
        .flatten()
        .map(|d| d.clone_data_column())
        .collect::<Vec<_>>();
    if malicious_withhold_count > 0 {
        let columns_to_keep = data_column_sidecars
            .len()
            .saturating_sub(malicious_withhold_count);
        // Randomize columns before dropping the last malicious_withhold_count items
        data_column_sidecars.shuffle(&mut rand::thread_rng());
        data_column_sidecars.truncate(columns_to_keep);
    }
    let pubsub_messages = data_column_sidecars
        .into_iter()
        .map(|data_col| {
            let subnet = DataColumnSubnetId::from_column_index::<T::EthSpec>(
                data_col.index as usize,
                &chain.spec,
            );
            PubsubMessage::DataColumnSidecar(Box::new((subnet, data_col)))
        })
        .collect::<Vec<_>>();
    crate::publish_pubsub_messages(sender_clone, pubsub_messages)
        .map_err(|_| BlockError::BeaconChainError(BeaconChainError::UnableToPublish))
}

fn publish_blob_sidecars<T: BeaconChainTypes>(
    sender_clone: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    blob: &GossipVerifiedBlob<T>,
) -> Result<(), BlockError> {
    let pubsub_message = PubsubMessage::BlobSidecar(Box::new((blob.index(), blob.clone_blob())));
    crate::publish_pubsub_message(sender_clone, pubsub_message)
        .map_err(|_| BlockError::BeaconChainError(BeaconChainError::UnableToPublish))
}

async fn post_block_import_logging_and_response<T: BeaconChainTypes>(
    result: Result<AvailabilityProcessingStatus, BlockError>,
    validation_level: BroadcastValidation,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    is_locally_built_block: bool,
    seen_timestamp: Duration,
    chain: &Arc<BeaconChain<T>>,
    log: &Logger,
) -> Result<Response, Rejection> {
    match result {
        // The `DuplicateFullyImported` case here captures the case where the block finishes
        // being imported after gossip verification. It could be that it finished imported as a
        // result of the block being imported from gossip, OR it could be that it finished importing
        // after processing of a gossip blob. In the latter case we MUST run fork choice to
        // re-compute the head.
        Ok(AvailabilityProcessingStatus::Imported(root))
        | Err(BlockError::DuplicateFullyImported(root)) => {
            let delay = get_block_delay_ms(seen_timestamp, block.message(), &chain.slot_clock);
            info!(
                log,
                "Valid block from HTTP API";
                "block_delay" => ?delay,
                "root" => %root,
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

            // Only perform late-block logging here if the block is local. For
            // blocks built with builders we consider the broadcast time to be
            // when the blinded block is published to the builder.
            if is_locally_built_block {
                late_block_logging(chain, seen_timestamp, block.message(), root, "local", log)
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
                error!(
                    log,
                    "Invalid block provided to HTTP API";
                    "reason" => ?e,
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
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
) -> Result<Response, Rejection> {
    let block_root = blinded_block.canonical_root();
    let full_block =
        reconstruct_block(chain.clone(), block_root, blinded_block, log.clone()).await?;
    publish_block::<T, _>(
        Some(block_root),
        full_block,
        chain,
        network_tx,
        log,
        validation_level,
        duplicate_status_code,
        network_globals,
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
) -> Result<ProvenancedBlock<T, Arc<SignedBeaconBlock<T::EthSpec>>>, Rejection> {
    let full_payload_opt = if let Ok(payload_header) = block.message().body().execution_payload() {
        let el = chain.execution_layer.as_ref().ok_or_else(|| {
            warp_utils::reject::custom_server_error("Missing execution layer".to_string())
        })?;

        // If the execution block hash is zero, use an empty payload.
        let full_payload_contents = if payload_header.block_hash() == ExecutionBlockHash::zero() {
            let fork_name = chain
                .spec
                .fork_name_at_epoch(block.slot().epoch(T::EthSpec::slots_per_epoch()));
            if fork_name == ForkName::Bellatrix {
                let payload: FullPayload<T::EthSpec> = FullPayloadBellatrix::default().into();
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
            .map(|full_block| ProvenancedBlock::local(Arc::new(full_block), None)),
        Some(ProvenancedPayload::Local(full_payload_contents)) => {
            into_full_block_and_blobs::<T>(block, full_payload_contents)
                .map(|(block, blobs)| ProvenancedBlock::local(block, blobs))
        }
        Some(ProvenancedPayload::Builder(full_payload_contents)) => {
            into_full_block_and_blobs::<T>(block, full_payload_contents)
                .map(|(block, blobs)| ProvenancedBlock::builder(block, blobs))
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
) -> Result<(), BlockError> {
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
#[allow(clippy::type_complexity)]
pub fn into_full_block_and_blobs<T: BeaconChainTypes>(
    blinded_block: SignedBlindedBeaconBlock<T::EthSpec>,
    maybe_full_payload_contents: FullPayloadContents<T::EthSpec>,
) -> Result<(Arc<SignedBeaconBlock<T::EthSpec>>, UnverifiedBlobs<T>), String> {
    match maybe_full_payload_contents {
        // This variant implies a pre-deneb block
        FullPayloadContents::Payload(execution_payload) => {
            let signed_block = blinded_block
                .try_into_full_block(Some(execution_payload))
                .ok_or("Failed to build full block with payload".to_string())?;
            Ok((Arc::new(signed_block), None))
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

            Ok((Arc::new(signed_block), Some((proofs, blobs))))
        }
    }
}
