use crate::block_id::BlockId;
use crate::publish_blocks::{check_slashable, publish_column_sidecars};
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    ChainFilter, EthV1Filter, NetworkTxFilter, NotWhileSyncingFilter, ResponseFilter,
    TaskSpawnerFilter,
};
use crate::version::{
    ResponseIncludesVersion, add_consensus_version_header, add_ssz_content_type_header,
    execution_optimistic_finalized_beacon_response,
};
use beacon_chain::data_column_verification::{GossipDataColumnError, GossipVerifiedDataColumn};
use beacon_chain::payload_envelope_verification::EnvelopeError;
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes, BlockError,
    NotifyExecutionLayer,
};
use bytes::Bytes;
use eth2::{
    BLOB_DATA_INCLUDED_HEADER, CONSENSUS_VERSION_HEADER,
    types::{self as api_types, BroadcastValidation, SignedExecutionPayloadEnvelopeContents},
};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::{Decode, Encode};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, warn};
use types::{BlockImportSource, EthSpec, ForkName, KzgProofs, SignedExecutionPayloadEnvelope};
use warp::{
    Filter, Rejection,
    http::response::Builder,
    reply::{Reply, Response},
};

/// Request body for `POST beacon/execution_payload_envelopes`, selected via the
/// `Eth-Blob-Data-Included` header.
pub enum SignedEnvelopeSubmission<E: EthSpec> {
    /// Envelope only (stateful flow); blobs and KZG proofs are taken from the node's
    /// pending payload envelope cache.
    EnvelopeOnly(Box<SignedExecutionPayloadEnvelope<E>>),
    /// Full envelope bundled with blobs and KZG proofs (stateless flow), allowing
    /// publication via a beacon node that did not build the payload.
    EnvelopeAndBlobData(Box<SignedExecutionPayloadEnvelopeContents<E>>),
}

fn ensure_gloas_consensus_version(fork_name: ForkName) -> Result<(), Rejection> {
    if !fork_name.gloas_enabled() {
        return Err(warp_utils::reject::custom_bad_request(format!(
            "Eth-Consensus-Version {fork_name} is not supported for execution payload envelopes"
        )));
    }
    Ok(())
}

impl<E: EthSpec> SignedEnvelopeSubmission<E> {
    fn from_ssz_bytes(blob_data_included: bool, bytes: &[u8]) -> Result<Self, Rejection> {
        let invalid_ssz = |e| warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"));
        Ok(if blob_data_included {
            Self::EnvelopeAndBlobData(Box::new(
                SignedExecutionPayloadEnvelopeContents::from_ssz_bytes(bytes)
                    .map_err(invalid_ssz)?,
            ))
        } else {
            Self::EnvelopeOnly(Box::new(
                SignedExecutionPayloadEnvelope::from_ssz_bytes(bytes).map_err(invalid_ssz)?,
            ))
        })
    }

    fn from_json(blob_data_included: bool, bytes: &[u8]) -> Result<Self, Rejection> {
        let invalid_json =
            |e| warp_utils::reject::custom_bad_request(format!("invalid JSON: {e:?}"));
        Ok(if blob_data_included {
            Self::EnvelopeAndBlobData(Box::new(
                serde_json::from_slice(bytes).map_err(invalid_json)?,
            ))
        } else {
            Self::EnvelopeOnly(Box::new(
                serde_json::from_slice(bytes).map_err(invalid_json)?,
            ))
        })
    }
}

// POST beacon/execution_payload_envelopes (SSZ)
pub(crate) fn post_beacon_execution_payload_envelopes_ssz<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelopes"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp::header::<ForkName>(CONSENSUS_VERSION_HEADER))
        .and(warp::header::<bool>(BLOB_DATA_INCLUDED_HEADER))
        .and(warp::body::bytes())
        .and(not_while_syncing_filter)
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |validation_level: api_types::BroadcastValidationQuery,
             fork_name: ForkName,
             blob_data_included: bool,
             body_bytes: Bytes,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    not_synced_filter?;
                    ensure_gloas_consensus_version(fork_name)?;
                    let submission =
                        SignedEnvelopeSubmission::from_ssz_bytes(blob_data_included, &body_bytes)?;
                    publish_execution_payload_envelope(
                        submission,
                        validation_level.broadcast_validation,
                        chain,
                        &network_tx,
                    )
                    .await
                })
            },
        )
        .boxed()
}

// POST beacon/execution_payload_envelopes
pub(crate) fn post_beacon_execution_payload_envelopes<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelopes"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp::header::<ForkName>(CONSENSUS_VERSION_HEADER))
        .and(warp::header::<bool>(BLOB_DATA_INCLUDED_HEADER))
        .and(warp::body::bytes())
        .and(not_while_syncing_filter)
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |validation_level: api_types::BroadcastValidationQuery,
             fork_name: ForkName,
             blob_data_included: bool,
             body_bytes: Bytes,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    not_synced_filter?;
                    ensure_gloas_consensus_version(fork_name)?;
                    let submission =
                        SignedEnvelopeSubmission::from_json(blob_data_included, &body_bytes)?;
                    publish_execution_payload_envelope(
                        submission,
                        validation_level.broadcast_validation,
                        chain,
                        &network_tx,
                    )
                    .await
                })
            },
        )
        .boxed()
}

/// Publishes a signed execution payload envelope to the network. Implements
/// `POST /eth/v1/beacon/execution_payload_envelopes` per the in-flight beacon-APIs PRs
/// <https://github.com/ethereum/beacon-APIs/pull/580> and
/// <https://github.com/ethereum/beacon-APIs/pull/624>.
pub async fn publish_execution_payload_envelope<T: BeaconChainTypes>(
    submission: SignedEnvelopeSubmission<T::EthSpec>,
    validation_level: BroadcastValidation,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response, Rejection> {
    if !chain.spec.is_gloas_scheduled() {
        return Err(warp_utils::reject::custom_bad_request(
            "Execution payload envelopes are not supported before the Gloas fork".into(),
        ));
    }

    let includes_blob_data = matches!(
        &submission,
        SignedEnvelopeSubmission::EnvelopeAndBlobData(_)
    );
    let (envelope, blobs_and_proofs) = match submission {
        SignedEnvelopeSubmission::EnvelopeAndBlobData(contents) => {
            let SignedExecutionPayloadEnvelopeContents {
                signed_execution_payload_envelope: envelope,
                kzg_proofs,
                blobs,
            } = *contents;
            let expected_proofs = blobs.len() * T::EthSpec::number_of_columns();
            if kzg_proofs.len() != expected_proofs {
                return Err(warp_utils::reject::custom_bad_request(format!(
                    "invalid number of kzg proofs: expected {}, got {}",
                    expected_proofs,
                    kzg_proofs.len()
                )));
            }
            (envelope, Some((Arc::new(blobs), Some(kzg_proofs))))
        }
        SignedEnvelopeSubmission::EnvelopeOnly(envelope) => {
            let blobs = chain
                .pending_payload_envelopes
                .write()
                .take_blobs(envelope.message.beacon_block_root);
            (*envelope, blobs.map(|blobs| (blobs, None)))
        }
    };

    let slot = envelope.slot();
    let beacon_block_root = envelope.message.beacon_block_root;

    info!(
        %slot,
        %beacon_block_root,
        builder_index = envelope.message.builder_index,
        "Publishing signed execution payload envelope to network"
    );

    // Spawn the column-build task (CPU-bound KZG cell-and-proof computation) before
    // publishing the envelope so it runs in parallel with envelope gossip, narrowing
    // the window in which peers see envelope-without-columns. If envelope import
    // fails below, dropping this future drops the spawned `JoinHandle` (the running
    // closure on the blocking pool finishes and is then discarded — no work cancellation).
    let column_build_future = match blobs_and_proofs {
        Some((blobs, cell_proofs)) if !blobs.is_empty() => {
            Some(spawn_build_gloas_data_columns_task(
                &chain,
                beacon_block_root,
                slot,
                blobs,
                cell_proofs,
            )?)
        }
        _ => None,
    };

    // Gossip-verify the envelope before publishing.
    let gossip_verified = chain
        .verify_envelope_for_gossip(Arc::new(envelope))
        .await
        .map_err(|e| {
            warn!(%slot, error = ?e, "Execution payload envelope failed gossip verification");
            warp_utils::reject::custom_bad_request(format!(
                "envelope failed gossip verification: {e}"
            ))
        })?;

    // Reject stateful submissions before broadcast when the block commits to blobs but the
    // node has none cached.
    if !includes_blob_data && column_build_future.is_none() {
        let commits_to_blobs = gossip_verified
            .block
            .message()
            .body()
            .signed_execution_payload_bid()
            .is_ok_and(|bid| !bid.message.blob_kzg_commitments.is_empty());
        if commits_to_blobs {
            return Err(warp_utils::reject::custom_bad_request(
                "block commits to blobs but the beacon node has no cached blobs and KZG proofs to attach"
                    .into(),
            ));
        }
    }

    let network_tx_clone = network_tx.clone();
    let block_for_equivocation_check = gossip_verified.block.clone();
    let envelope_for_gossip = gossip_verified.signed_envelope.clone();
    let publish_envelope = || {
        crate::utils::publish_pubsub_message(
            &network_tx_clone,
            PubsubMessage::ExecutionPayload(Box::new(envelope_for_gossip.as_ref().clone())),
        )
        .map_err(|_| {
            EnvelopeError::BeaconChainError(Box::new(
                beacon_chain::BeaconChainError::UnableToPublish,
            ))
        })
    };

    let published = AtomicBool::new(false);
    if validation_level == BroadcastValidation::Gossip {
        publish_envelope().map_err(|_| {
            warp_utils::reject::custom_server_error(
                "unable to publish to network channel".to_string(),
            )
        })?;
        published.store(true, Ordering::SeqCst);
    }

    let publish_fn = || {
        match validation_level {
            BroadcastValidation::Gossip => return Ok(()),
            BroadcastValidation::Consensus => {}
            BroadcastValidation::ConsensusAndEquivocation => {
                check_slashable(&chain, beacon_block_root, &block_for_equivocation_check).map_err(
                    |e| match e {
                        BlockError::BeaconChainError(e) => EnvelopeError::BeaconChainError(e),
                        e => EnvelopeError::InternalError(format!("{e:?}")),
                    },
                )?;
            }
        }

        publish_envelope()?;
        published.store(true, Ordering::SeqCst);
        Ok(())
    };

    let import_result = chain
        .process_execution_payload_envelope(
            beacon_block_root,
            gossip_verified,
            NotifyExecutionLayer::Yes,
            BlockImportSource::HttpApi,
            publish_fn,
        )
        .await;

    let mut envelope_imported = match import_result {
        Ok(AvailabilityProcessingStatus::Imported(_, _)) => true,
        Ok(AvailabilityProcessingStatus::MissingComponents(_, _)) => false,
        Err(e) => {
            if is_unable_to_publish(&e) {
                return Err(warp_utils::reject::custom_server_error(
                    "unable to publish to network channel".to_string(),
                ));
            }

            if published.load(Ordering::SeqCst) {
                warn!(%slot, error = ?e, "Failed to import execution payload envelope after broadcast");
                return Err(warp_utils::reject::broadcast_without_import(format!(
                    "envelope import failed: {e:?}"
                )));
            }

            warn!(%slot, error = ?e, "Rejecting execution payload envelope before broadcast");
            return Err(warp_utils::reject::custom_bad_request(format!(
                "envelope rejected: {e:?}"
            )));
        }
    };

    // The envelope has already been published over gossip, only columns can fail from here.
    // `EnvelopeAndBlobData`: the caller still holds the blobs so we return an error. The caller
    // can retry against a different beacon node.
    // `EnvelopeOnly`: the cached blobs have been consumed, a retry cannot rebuild the columns. We
    // also cant retry against another beacon node. So we just log a failure and continue.
    if let Some(column_build_future) = column_build_future {
        match column_build_future.await {
            Ok(columns) => {
                match publish_and_import_columns(&chain, network_tx, slot, columns).await {
                    Ok(imported) => {
                        if imported {
                            envelope_imported = true;
                        }
                    }
                    Err(rejection) => {
                        if includes_blob_data {
                            return Err(rejection);
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    %slot,
                    error = ?e,
                    "Failed to build data columns after envelope publication"
                );
                if includes_blob_data {
                    return Err(e);
                }
            }
        }
    }

    // Return 202 when broadcast succeeds but integration does not. Unlike the block path,
    // 202 applies at every validation level: missing components here are node-cached columns
    // rather than request-supplied blobs, so incomplete import is not the submitter's fault.
    if envelope_imported {
        chain.recompute_head_at_current_slot().await;
        Ok(warp::reply().into_response())
    } else {
        Err(warp_utils::reject::broadcast_without_import(format!(
            "envelope for slot {slot} was broadcast but not fully imported"
        )))
    }
}

/// Publishes locally-built data columns and imports the node's sampling subset.
///
/// Returns `Ok(true)` if envelope import was completed.
/// Returns `Err` on publication failure.
async fn publish_and_import_columns<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    slot: types::Slot,
    gossip_verified_columns: Vec<GossipVerifiedDataColumn<T>>,
) -> Result<bool, Rejection> {
    if gossip_verified_columns.is_empty() {
        return Ok(false);
    }

    if let Err(e) = publish_column_sidecars(network_tx, &gossip_verified_columns, chain) {
        error!(
            %slot,
            error = ?e,
            "Failed to publish data column sidecars after envelope publication"
        );
        return Err(warp_utils::reject::custom_server_error(format!(
            "failed to publish data column sidecars: {e:?}"
        )));
    }

    let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
    let sampling_column_indices = chain.custody_context.sampling_columns_for_epoch(epoch);
    let sampling_columns = gossip_verified_columns
        .into_iter()
        .filter(|col| sampling_column_indices.contains(&col.index()))
        .collect::<Vec<_>>();

    if sampling_columns.is_empty() {
        return Ok(false);
    }

    match Box::pin(chain.process_gossip_data_columns(sampling_columns, || Ok(()))).await {
        Ok(AvailabilityProcessingStatus::Imported(_, _)) => Ok(true),
        Ok(AvailabilityProcessingStatus::MissingComponents(_, _)) => Ok(false),
        Err(e) => {
            error!(
                %slot,
                error = ?e,
                "Failed to process sampling data columns during envelope publication"
            );
            Ok(false)
        }
    }
}

fn is_unable_to_publish(error: &BlockError) -> bool {
    match error {
        BlockError::BeaconChainError(error) => {
            matches!(error.as_ref(), BeaconChainError::UnableToPublish)
        }
        BlockError::EnvelopeError(error) => matches!(
            error.as_ref(),
            EnvelopeError::BeaconChainError(error)
                if matches!(error.as_ref(), BeaconChainError::UnableToPublish)
        ),
        _ => false,
    }
}

fn spawn_build_gloas_data_columns_task<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    beacon_block_root: types::Hash256,
    slot: types::Slot,
    blobs: Arc<types::BlobsList<T::EthSpec>>,
    cell_proofs: Option<KzgProofs<T::EthSpec>>,
) -> Result<impl Future<Output = Result<Vec<GossipVerifiedDataColumn<T>>, Rejection>>, Rejection> {
    let chain_for_build = chain.clone();
    let handle = chain
        .task_executor
        .spawn_blocking_handle(
            move || {
                build_gloas_data_columns(
                    &chain_for_build,
                    beacon_block_root,
                    slot,
                    &blobs,
                    cell_proofs,
                )
            },
            "build_gloas_data_columns",
        )
        .ok_or_else(|| warp_utils::reject::custom_server_error("runtime shutdown".to_string()))?;

    Ok(async move {
        handle
            .await
            .map_err(|_| warp_utils::reject::custom_server_error("join error".to_string()))?
    })
}

fn build_gloas_data_columns<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    beacon_block_root: types::Hash256,
    slot: types::Slot,
    blobs: &types::BlobsList<T::EthSpec>,
    cell_proofs: Option<KzgProofs<T::EthSpec>>,
) -> Result<Vec<GossipVerifiedDataColumn<T>>, Rejection> {
    let blob_refs: Vec<_> = blobs.iter().collect();
    let data_column_sidecars = match cell_proofs {
        Some(proofs) => beacon_chain::kzg_utils::blobs_to_data_column_sidecars_gloas_with_proofs(
            &blob_refs,
            proofs.to_vec(),
            beacon_block_root,
            slot,
            &chain.kzg,
            &chain.spec,
        ),
        None => beacon_chain::kzg_utils::blobs_to_data_column_sidecars_gloas(
            &blob_refs,
            beacon_block_root,
            slot,
            &chain.kzg,
            &chain.spec,
        ),
    }
    .map_err(|e| {
        error!(
            error = ?e,
            %slot,
            "Failed to build data column sidecars for envelope"
        );
        warp_utils::reject::custom_server_error(format!("{e:?}"))
    })?;

    let gossip_verified_columns = data_column_sidecars
        .into_iter()
        .filter_map(|col| {
            let index = *col.index();
            match GossipVerifiedDataColumn::new_for_block_publishing(col, chain) {
                Ok(verified) => Some(verified),
                Err(GossipDataColumnError::PriorKnown { .. }) => None,
                Err(e) => {
                    warn!(
                        %slot,
                        column_index = index,
                        error = ?e,
                        "Locally-built data column failed gossip verification"
                    );
                    None
                }
            }
        })
        .collect::<Vec<_>>();

    debug!(
        %slot,
        column_count = gossip_verified_columns.len(),
        "Built data columns for envelope publication"
    );

    Ok(gossip_verified_columns)
}

// GET beacon/execution_payload_envelopes/{block_id}
pub(crate) fn get_beacon_execution_payload_envelopes<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    block_id_or_err: impl Filter<Extract = (BlockId,), Error = Rejection>
    + Clone
    + Send
    + Sync
    + 'static,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelopes"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (root, execution_optimistic, finalized) = block_id.root(&chain)?;

                    let envelope = chain
                        .get_payload_envelope(&root)
                        .map_err(warp_utils::reject::unhandled_error)?
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "execution payload envelope for block root {root}"
                            ))
                        })?;

                    let fork_name = chain.spec.fork_name_at_slot::<T::EthSpec>(envelope.slot());

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Builder::new()
                            .status(200)
                            .body(envelope.as_ssz_bytes())
                            .map(add_ssz_content_type_header)
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => {
                            let res = execution_optimistic_finalized_beacon_response(
                                ResponseIncludesVersion::Yes(fork_name),
                                execution_optimistic,
                                finalized,
                                &envelope,
                            )?;
                            Ok(warp::reply::json(&res).into_response())
                        }
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        )
        .boxed()
}
