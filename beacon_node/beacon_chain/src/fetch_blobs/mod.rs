//! This module implements an optimisation to fetch blobs via JSON-RPC from the EL.
//! If a blob has already been seen in the public mempool, then it is often unnecessary to wait for
//! it to arrive on P2P gossip. This PR uses a new JSON-RPC method (`engine_getBlobsV1`) which
//! allows the CL to load the blobs quickly from the EL's blob pool.
//!
//! Once the node fetches the blobs from EL, it then publishes the remaining blobs that it hasn't seen
//! on P2P gossip to the network. From PeerDAS onwards, together with the increase in blob count,
//! broadcasting blobs requires a much higher bandwidth, and is only done by high capacity
//! supernodes.

mod fetch_blobs_beacon_adapter;
#[cfg(test)]
mod tests;

use crate::blob_verification::{GossipBlobError, KzgVerifiedBlob};
use crate::block_verification_types::AsBlock;
use crate::data_column_verification::{KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn};
#[cfg_attr(test, double)]
use crate::fetch_blobs::fetch_blobs_beacon_adapter::FetchBlobsBeaconAdapter;
use crate::kzg_utils::blobs_to_data_column_sidecars;
use crate::observed_block_producers::ProposalKey;
use crate::validator_monitor::timestamp_now;
use crate::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes, BlockError,
    metrics,
};
use execution_layer::Error as ExecutionLayerError;
use execution_layer::json_structures::{BlobAndProofV1, BlobAndProofV2};
use metrics::{TryExt, inc_counter};
#[cfg(test)]
use mockall_double::double;
use ssz_types::FixedVector;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::sync::Arc;
use tracing::{Span, debug, instrument, warn};
use types::blob_sidecar::BlobSidecarError;
use types::data_column_sidecar::DataColumnSidecarError;
use types::{
    BeaconStateError, Blob, BlobSidecar, ColumnIndex, EthSpec, FullPayload, Hash256, KzgProofs,
    SignedBeaconBlock, SignedBeaconBlockHeader, VersionedHash,
};

/// Result from engine get blobs to be passed onto `DataAvailabilityChecker` and published to the
/// gossip network. The blobs / data columns have not been marked as observed yet, as they may not
/// be published immediately.
#[derive(Debug)]
pub enum EngineGetBlobsOutput<T: BeaconChainTypes> {
    Blobs(Vec<KzgVerifiedBlob<T::EthSpec>>),
    /// A filtered list of custody data columns to be imported into the `DataAvailabilityChecker`.
    CustodyColumns(Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>),
}

#[derive(Debug)]
pub enum FetchEngineBlobError {
    BeaconStateError(BeaconStateError),
    BeaconChainError(Box<BeaconChainError>),
    BlobProcessingError(BlockError),
    BlobSidecarError(BlobSidecarError),
    DataColumnSidecarError(DataColumnSidecarError),
    ExecutionLayerMissing,
    InternalError(String),
    GossipBlob(GossipBlobError),
    KzgError(kzg::Error),
    RequestFailed(ExecutionLayerError),
    RuntimeShutdown,
    TokioJoin(tokio::task::JoinError),
}

/// Fetches blobs from the EL mempool and processes them. It also broadcasts unseen blobs or
/// data columns (PeerDAS onwards) to the network, using the supplied `publish_fn`.
#[instrument(skip_all)]
pub async fn fetch_and_process_engine_blobs<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    custody_columns: &[ColumnIndex],
    publish_fn: impl Fn(EngineGetBlobsOutput<T>) + Send + 'static,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    fetch_and_process_engine_blobs_inner(
        FetchBlobsBeaconAdapter::new(chain),
        block_root,
        block,
        custody_columns,
        publish_fn,
    )
    .await
}

/// Internal implementation of fetch blobs, which uses `FetchBlobsBeaconAdapter` instead of
/// `BeaconChain` for better testability.
async fn fetch_and_process_engine_blobs_inner<T: BeaconChainTypes>(
    chain_adapter: FetchBlobsBeaconAdapter<T>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    custody_columns: &[ColumnIndex],
    publish_fn: impl Fn(EngineGetBlobsOutput<T>) + Send + 'static,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    let versioned_hashes = if let Some(kzg_commitments) = block
        .message()
        .body()
        .blob_kzg_commitments()
        .ok()
        .filter(|blobs| !blobs.is_empty())
    {
        kzg_commitments
            .iter()
            .map(kzg_commitment_to_versioned_hash)
            .collect::<Vec<_>>()
    } else {
        debug!("Fetch blobs not triggered - none required");
        return Ok(None);
    };

    debug!(
        num_expected_blobs = versioned_hashes.len(),
        "Fetching blobs from the EL"
    );

    if chain_adapter
        .spec()
        .is_peer_das_enabled_for_epoch(block.epoch())
    {
        fetch_and_process_blobs_v2(
            chain_adapter,
            block_root,
            block,
            versioned_hashes,
            custody_columns,
            publish_fn,
        )
        .await
    } else {
        fetch_and_process_blobs_v1(
            chain_adapter,
            block_root,
            block,
            versioned_hashes,
            publish_fn,
        )
        .await
    }
}

#[instrument(skip_all, level = "debug")]
async fn fetch_and_process_blobs_v1<T: BeaconChainTypes>(
    chain_adapter: FetchBlobsBeaconAdapter<T>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    versioned_hashes: Vec<VersionedHash>,
    publish_fn: impl Fn(EngineGetBlobsOutput<T>) + Send + Sized,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    let num_expected_blobs = versioned_hashes.len();
    metrics::observe(&metrics::BLOBS_FROM_EL_EXPECTED, num_expected_blobs as f64);
    debug!(num_expected_blobs, "Fetching blobs from the EL");
    let response = chain_adapter
        .get_blobs_v1(versioned_hashes)
        .await
        .inspect_err(|_| {
            inc_counter(&metrics::BLOBS_FROM_EL_ERROR_TOTAL);
        })?;

    let num_fetched_blobs = response.iter().filter(|opt| opt.is_some()).count();
    metrics::observe(&metrics::BLOBS_FROM_EL_RECEIVED, num_fetched_blobs as f64);

    if num_fetched_blobs == 0 {
        debug!(num_expected_blobs, "No blobs fetched from the EL");
        inc_counter(&metrics::BLOBS_FROM_EL_MISS_TOTAL);
        return Ok(None);
    } else {
        debug!(
            num_expected_blobs,
            num_fetched_blobs, "Received blobs from the EL"
        );
        inc_counter(&metrics::BLOBS_FROM_EL_HIT_TOTAL);
    }

    if chain_adapter.fork_choice_contains_block(&block_root) {
        // Avoid computing sidecars if the block has already been imported.
        debug!(
            info = "block has already been imported",
            "Ignoring EL blobs response"
        );
        return Ok(None);
    }

    let (signed_block_header, kzg_commitments_proof) = block
        .signed_block_header_and_kzg_commitments_proof()
        .map_err(FetchEngineBlobError::BeaconStateError)?;

    let mut blob_sidecar_list = build_blob_sidecars(
        &block,
        response,
        signed_block_header,
        &kzg_commitments_proof,
    )?;

    if let Some(observed_blobs) =
        chain_adapter.blobs_known_for_proposal(block.message().proposer_index(), block.slot())
    {
        blob_sidecar_list.retain(|blob| !observed_blobs.contains(&blob.blob_index()));
        if blob_sidecar_list.is_empty() {
            debug!(
                info = "blobs have already been seen on gossip",
                "Ignoring EL blobs response"
            );
            return Ok(None);
        }
    }

    if let Some(known_blobs) = chain_adapter.cached_blob_indexes(&block_root) {
        blob_sidecar_list.retain(|blob| !known_blobs.contains(&blob.blob_index()));
        if blob_sidecar_list.is_empty() {
            debug!(
                info = "blobs have already been imported into data availability checker",
                "Ignoring EL blobs response"
            );
            return Ok(None);
        }
    }

    // Up until this point we have not observed the blobs in the gossip cache, which allows them to
    // arrive independently while this function is running. In `publish_fn` we will observe them
    // and then publish any blobs that had not already been observed.
    publish_fn(EngineGetBlobsOutput::Blobs(blob_sidecar_list.clone()));

    let availability_processing_status = chain_adapter
        .process_engine_blobs(
            block.slot(),
            block_root,
            EngineGetBlobsOutput::Blobs(blob_sidecar_list),
        )
        .await?;

    Ok(Some(availability_processing_status))
}

#[instrument(skip_all, level = "debug")]
async fn fetch_and_process_blobs_v2<T: BeaconChainTypes>(
    chain_adapter: FetchBlobsBeaconAdapter<T>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    versioned_hashes: Vec<VersionedHash>,
    custody_columns_indices: &[ColumnIndex],
    publish_fn: impl Fn(EngineGetBlobsOutput<T>) + Send + 'static,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    let num_expected_blobs = versioned_hashes.len();

    metrics::observe(&metrics::BLOBS_FROM_EL_EXPECTED, num_expected_blobs as f64);
    debug!(num_expected_blobs, "Fetching blobs from the EL");
    let response = chain_adapter
        .get_blobs_v2(versioned_hashes)
        .await
        .inspect_err(|_| {
            inc_counter(&metrics::BLOBS_FROM_EL_ERROR_TOTAL);
        })?;

    let Some(blobs_and_proofs) = response else {
        debug!(num_expected_blobs, "No blobs fetched from the EL");
        inc_counter(&metrics::BLOBS_FROM_EL_MISS_TOTAL);
        return Ok(None);
    };

    let (blobs, proofs): (Vec<_>, Vec<_>) = blobs_and_proofs
        .into_iter()
        .map(|blob_and_proof| {
            let BlobAndProofV2 { blob, proofs } = blob_and_proof;
            (blob, proofs)
        })
        .unzip();

    let num_fetched_blobs = blobs.len();
    metrics::observe(&metrics::BLOBS_FROM_EL_RECEIVED, num_fetched_blobs as f64);

    if num_fetched_blobs != num_expected_blobs {
        // This scenario is not supposed to happen if the EL is spec compliant.
        // It should either return all requested blobs or none, but NOT partial responses.
        // If we attempt to compute columns with partial blobs, we'd end up with invalid columns.
        warn!(
            num_fetched_blobs,
            num_expected_blobs, "The EL did not return all requested blobs"
        );
        inc_counter(&metrics::BLOBS_FROM_EL_MISS_TOTAL);
        return Ok(None);
    }

    debug!(num_fetched_blobs, "All expected blobs received from the EL");
    inc_counter(&metrics::BLOBS_FROM_EL_HIT_TOTAL);

    if chain_adapter.fork_choice_contains_block(&block_root) {
        // Avoid computing columns if the block has already been imported.
        debug!(
            info = "block has already been imported",
            "Ignoring EL blobs response"
        );
        return Ok(None);
    }

    let chain_adapter = Arc::new(chain_adapter);
    let custody_columns_to_import = compute_custody_columns_to_import(
        &chain_adapter,
        block_root,
        block.clone(),
        blobs,
        proofs,
        custody_columns_indices,
    )
    .await?;

    if custody_columns_to_import.is_empty() {
        debug!(
            info = "No new data columns to import",
            "Ignoring EL blobs response"
        );
        return Ok(None);
    }

    // Up until this point we have not observed the data columns in the gossip cache, which allows
    // them to arrive independently while this function is running. In publish_fn we will observe
    // them and then publish any columns that had not already been observed.
    publish_fn(EngineGetBlobsOutput::CustodyColumns(
        custody_columns_to_import.clone(),
    ));

    let availability_processing_status = chain_adapter
        .process_engine_blobs(
            block.slot(),
            block_root,
            EngineGetBlobsOutput::CustodyColumns(custody_columns_to_import),
        )
        .await?;

    Ok(Some(availability_processing_status))
}

/// Offload the data column computation to a blocking task to avoid holding up the async runtime.
async fn compute_custody_columns_to_import<T: BeaconChainTypes>(
    chain_adapter: &Arc<FetchBlobsBeaconAdapter<T>>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    blobs: Vec<Blob<T::EthSpec>>,
    proofs: Vec<KzgProofs<T::EthSpec>>,
    custody_columns_indices: &[ColumnIndex],
) -> Result<Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>, FetchEngineBlobError> {
    let kzg = chain_adapter.kzg().clone();
    let spec = chain_adapter.spec().clone();
    let chain_adapter_cloned = chain_adapter.clone();
    let custody_columns_indices = custody_columns_indices.to_vec();
    let current_span = Span::current();
    chain_adapter
        .executor()
        .spawn_blocking_handle(
            move || {
                let _guard = current_span.enter();
                let mut timer = metrics::start_timer_vec(
                    &metrics::DATA_COLUMN_SIDECAR_COMPUTATION,
                    &[&blobs.len().to_string()],
                );

                let blob_refs = blobs.iter().collect::<Vec<_>>();
                let cell_proofs = proofs.into_iter().flatten().collect();
                let data_columns_result =
                    blobs_to_data_column_sidecars(&blob_refs, cell_proofs, &block, &kzg, &spec)
                        .discard_timer_on_break(&mut timer);
                drop(timer);

                // This filtering ensures we only import and publish the custody columns.
                // `DataAvailabilityChecker` requires a strict match on custody columns count to
                // consider a block available.
                let mut custody_columns = data_columns_result
                    .map(|data_columns| {
                        data_columns
                            .into_iter()
                            .filter(|col| custody_columns_indices.contains(&col.index))
                            .map(|col| {
                                KzgVerifiedCustodyDataColumn::from_asserted_custody(
                                    KzgVerifiedDataColumn::from_execution_verified(col),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .map_err(FetchEngineBlobError::DataColumnSidecarError)?;

                // Only consider columns that are not already observed on gossip.
                if let Some(observed_columns) = chain_adapter_cloned.data_column_known_for_proposal(
                    ProposalKey::new(block.message().proposer_index(), block.slot()),
                ) {
                    custody_columns.retain(|col| !observed_columns.contains(&col.index()));
                    if custody_columns.is_empty() {
                        return Ok(vec![]);
                    }
                }

                // Only consider columns that are not already known to data availability.
                if let Some(known_columns) =
                    chain_adapter_cloned.cached_data_column_indexes(&block_root)
                {
                    custody_columns.retain(|col| !known_columns.contains(&col.index()));
                    if custody_columns.is_empty() {
                        return Ok(vec![]);
                    }
                }

                Ok(custody_columns)
            },
            "compute_custody_columns_to_import",
        )
        .ok_or(FetchEngineBlobError::RuntimeShutdown)?
        .await
        .map_err(FetchEngineBlobError::TokioJoin)?
}

fn build_blob_sidecars<E: EthSpec>(
    block: &Arc<SignedBeaconBlock<E, FullPayload<E>>>,
    response: Vec<Option<BlobAndProofV1<E>>>,
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitments_inclusion_proof: &FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
) -> Result<Vec<KzgVerifiedBlob<E>>, FetchEngineBlobError> {
    let mut sidecars = vec![];
    for (index, blob_and_proof) in response
        .into_iter()
        .enumerate()
        .filter_map(|(index, opt_blob)| Some((index, opt_blob?)))
    {
        let blob_sidecar = BlobSidecar::new_with_existing_proof(
            index,
            blob_and_proof.blob,
            block,
            signed_block_header.clone(),
            kzg_commitments_inclusion_proof,
            blob_and_proof.proof,
        )
        .map_err(FetchEngineBlobError::BlobSidecarError)?;

        sidecars.push(KzgVerifiedBlob::from_execution_verified(
            Arc::new(blob_sidecar),
            timestamp_now(),
        ));
    }

    Ok(sidecars)
}
