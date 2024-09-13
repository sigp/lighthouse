//! This module implements an optimisation to fetch blobs via JSON-RPC from the EL.
//! If a blob has already been seen in the public mempool, then it is often unnecessary to wait for
//! it to arrive on P2P gossip. This PR uses a new JSON-RPC method (`engine_getBlobsV1`) which
//! allows the CL to load the blobs quickly from the EL's blob pool.
//!
//! Once the node fetches the blobs from EL, it then publishes the remaining blobs that hasn't seen
//! on P2P gossip to the network. From PeerDAS onwards, together with the increase in blob count,
//! broadcasting blobs requires a much higher bandwidth, and is only done by high capacity
//! supernodes.
use crate::kzg_utils::blobs_to_data_column_sidecars;
use crate::observed_data_sidecars::ObservableDataSidecar;
use crate::{metrics, AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes, BlockError};
use execution_layer::json_structures::BlobAndProofV1;
use execution_layer::Error as ExecutionLayerError;
use itertools::Either;
use lighthouse_metrics::{inc_counter, TryExt};
use rand::prelude::SliceRandom;
use slog::{debug, error, warn};
use ssz_types::FixedVector;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::sync::Arc;
use std::time::Duration;
use types::blob_sidecar::{BlobSidecarError, FixedBlobSidecarList};
use types::{
    BeaconStateError, BlobSidecar, DataColumnSidecarList, EthSpec, FullPayload, Hash256,
    SignedBeaconBlock, SignedBeaconBlockHeader,
};

/// Number of batches that supernodes split data columns into during publishing.
pub const SUPERNODE_DATA_COLUMN_PUBLICATION_BATCHES: usize = 4;

/// The delay applied by supernodes between the sending of each data column batch.
pub const SUPERNODE_DATA_COLUMN_PUBLICATION_BATCH_INTERVAL: Duration = Duration::from_millis(200);

pub enum BlobsOrDataColumns<E: EthSpec> {
    Blobs(Vec<Arc<BlobSidecar<E>>>),
    DataColumns(DataColumnSidecarList<E>),
}

#[derive(Debug)]
pub enum FetchEngineBlobError {
    BeaconStateError(BeaconStateError),
    BlobProcessingError(BlockError),
    BlobSidecarError(BlobSidecarError),
    ExecutionLayerMissing,
    InternalError(String),
    RequestFailed(ExecutionLayerError),
    RuntimeShutdown,
}

/// Fetches blobs from the EL mempool and processes them. It also broadcasts unseen blobs or
/// data columns (PeerDAS onwards) to the network, using the supplied `publish_fn`.
pub async fn fetch_and_process_engine_blobs<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    publish_fn: impl Fn(BlobsOrDataColumns<T::EthSpec>) + Send + 'static,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    let versioned_hashes =
        if let Ok(kzg_commitments) = block.message().body().blob_kzg_commitments() {
            kzg_commitments
                .iter()
                .map(kzg_commitment_to_versioned_hash)
                .collect()
        } else {
            vec![]
        };
    let num_expected_blobs = versioned_hashes.len();

    if versioned_hashes.is_empty() {
        debug!(chain.log, "Blobs from EL - none required");
        return Ok(None);
    }

    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(FetchEngineBlobError::ExecutionLayerMissing)?;

    debug!(
        chain.log,
        "Blobs from EL - start request";
        "num_expected_blobs" => num_expected_blobs,
    );
    let response = execution_layer
        .get_blobs(versioned_hashes)
        .await
        .map_err(FetchEngineBlobError::RequestFailed)?;
    let num_fetched_blobs = response.iter().filter(|b| b.is_some()).count();
    let all_blobs_fetched = num_fetched_blobs == num_expected_blobs;

    let (signed_block_header, kzg_commitments_proof) = block
        .signed_block_header_and_kzg_commitments_proof()
        .map_err(FetchEngineBlobError::BeaconStateError)?;

    let fixed_blob_sidecar_list = build_blob_sidecars(
        &block,
        response,
        signed_block_header,
        &kzg_commitments_proof,
    )?;

    // Spawn an async task here for long computation tasks, so it doesn't block processing, and it
    // allows blobs / data columns to propagate without waiting for processing.
    //
    // An `mpsc::Sender` is then used to send the produced data columns to the `beacon_chain` for it
    // to be persisted, **after** the block is made attestable.
    //
    // The reason for doing this is to make the block available and attestable as soon as possible,
    // while maintaining the invariant that block and data columns are persisted atomically.
    let peer_das_enabled = chain.spec.is_peer_das_enabled_for_epoch(block.epoch());

    // Partial blobs response isn't useful for PeerDAS, so we don't bother building and publishing data columns.
    let data_columns_receiver_opt = if peer_das_enabled {
        if !all_blobs_fetched {
            debug!(
                chain.log,
                "Not all blobs fetched from the EL";
                "num_fetched_blobs" => num_fetched_blobs,
                "num_expected_blobs" => num_expected_blobs,
            );
            inc_counter(&metrics::BLOBS_FROM_EL_MISS_TOTAL);
            return Ok(None);
        }

        inc_counter(&metrics::BLOBS_FROM_EL_HIT_TOTAL);

        let logger = chain.log.clone();
        let block_cloned = block.clone();
        let kzg = chain.kzg.clone().expect("KZG not initialized");
        let spec = chain.spec.clone();
        let blobs_cloned = fixed_blob_sidecar_list.clone();
        let chain_cloned = chain.clone();
        let (data_columns_sender, data_columns_receiver) = tokio::sync::mpsc::channel(1);
        chain
            .task_executor
            .spawn_handle(
                async move {
                    let mut timer = metrics::start_timer_vec(
                        &metrics::DATA_COLUMN_SIDECAR_COMPUTATION,
                        &[&blobs_cloned.len().to_string()],
                    );
                    let blob_refs = blobs_cloned
                        .iter()
                        .filter_map(|b| b.as_ref().map(|b| &b.blob))
                        .collect::<Vec<_>>();
                    let data_columns_result =
                        blobs_to_data_column_sidecars(&blob_refs, &block_cloned, &kzg, &spec)
                            .discard_timer_on_break(&mut timer);
                    drop(timer);

                    let mut all_data_columns = match data_columns_result {
                        Ok(d) => d,
                        Err(e) => {
                            error!(
                                logger,
                                "Failed to build data column sidecars from blobs";
                                "error" => ?e
                            );
                            return;
                        }
                    };

                    if let Err(e) = data_columns_sender.try_send(all_data_columns.clone()) {
                        error!(logger, "Failed to send computed data columns"; "error" => ?e);
                    };

                    // Check indices from cache before sending the columns, to make sure we don't
                    // publish components already seen on gossip.
                    let is_supernode = chain_cloned
                        .data_availability_checker
                        .get_custody_columns_count()
                        == spec.number_of_columns;

                    // At the moment non supernodes are not required to publish any columns.
                    // TODO(das): we could experiment with having full nodes publish their custodied
                    // columns here.
                    if !is_supernode {
                        return;
                    }

                    // To reduce bandwidth for supernodes: permute the columns to publish and
                    // publish them in batches. Our hope is that some columns arrive from
                    // other supernodes in the meantime, obviating the need for us to publish
                    // them. If no other publisher exists for a column, it will eventually get
                    // published here.
                    // FIXME(das): deduplicate this wrt to gossip/sync methods
                    all_data_columns.shuffle(&mut rand::thread_rng());

                    let batch_size =
                        all_data_columns.len() / SUPERNODE_DATA_COLUMN_PUBLICATION_BATCHES;
                    for batch in all_data_columns.chunks(batch_size) {
                        let already_seen = chain_cloned
                            .data_availability_checker
                            .imported_custody_column_indexes(&block_root)
                            .unwrap_or_default();
                        let publishable = batch
                            .iter()
                            .filter(|col| !already_seen.contains(&col.index()))
                            .cloned()
                            .collect::<Vec<_>>();
                        if !publishable.is_empty() {
                            debug!(
                                chain_cloned.log,
                                "Publishing data columns from EL";
                                "count" => publishable.len()
                            );
                            publish_fn(BlobsOrDataColumns::DataColumns(publishable));
                        }
                        tokio::time::sleep(SUPERNODE_DATA_COLUMN_PUBLICATION_BATCH_INTERVAL).await;
                    }
                },
                "compute_data_columns",
            )
            .ok_or(FetchEngineBlobError::RuntimeShutdown)?;

        Some(data_columns_receiver)
    } else {
        if num_fetched_blobs == 0 {
            debug!(
                chain.log,
                "No blobs fetched from the EL";
                "num_expected_blobs" => num_expected_blobs,
            );
            inc_counter(&metrics::BLOBS_FROM_EL_MISS_TOTAL);
            return Ok(None);
        }

        inc_counter(&metrics::BLOBS_FROM_EL_HIT_TOTAL);

        let all_blobs = fixed_blob_sidecar_list.clone();
        let all_blobs_iter = all_blobs.into_iter().flat_map(|b| b.clone());

        let blobs_to_publish = match chain
            .data_availability_checker
            .imported_blob_indexes(&block_root)
        {
            None => Either::Left(all_blobs_iter),
            Some(imported_blob_indices) => Either::Right(
                all_blobs_iter.filter(move |b| !imported_blob_indices.contains(&b.index())),
            ),
        };

        publish_fn(BlobsOrDataColumns::Blobs(
            blobs_to_publish.collect::<Vec<_>>(),
        ));

        None
    };

    debug!(
        chain.log,
        "Blobs from EL - start processing";
        "num_fetched_blobs" => num_fetched_blobs,
    );

    let availability_processing_status = chain
        .process_engine_blobs(
            block.slot(),
            block_root,
            fixed_blob_sidecar_list.clone(),
            data_columns_receiver_opt,
        )
        .await
        .map_err(|e| FetchEngineBlobError::BlobProcessingError(e))?;

    Ok(Some(availability_processing_status))
}

fn build_blob_sidecars<E: EthSpec>(
    block: &Arc<SignedBeaconBlock<E, FullPayload<E>>>,
    response: Vec<Option<BlobAndProofV1<E>>>,
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitments_proof: &FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
) -> Result<FixedBlobSidecarList<E>, FetchEngineBlobError> {
    let mut fixed_blob_sidecar_list = FixedBlobSidecarList::default();
    for (i, blob_and_proof) in response
        .into_iter()
        .enumerate()
        .filter_map(|(i, opt_blob)| Some((i, opt_blob?)))
    {
        match BlobSidecar::new_with_existing_proof(
            i,
            blob_and_proof.blob,
            block,
            signed_block_header.clone(),
            kzg_commitments_proof,
            blob_and_proof.proof,
        ) {
            Ok(blob) => {
                if let Some(blob_mut) = fixed_blob_sidecar_list.get_mut(i) {
                    *blob_mut = Some(Arc::new(blob));
                } else {
                    return Err(FetchEngineBlobError::InternalError(
                        "Unreachable: Blobs from EL - out of bounds".to_string(),
                    ));
                }
            }
            Err(e) => {
                return Err(FetchEngineBlobError::BlobSidecarError(e));
            }
        }
    }
    Ok(fixed_blob_sidecar_list)
}
