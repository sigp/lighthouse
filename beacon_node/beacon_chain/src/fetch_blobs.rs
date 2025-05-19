//! This module implements an optimisation to fetch blobs via JSON-RPC from the EL.
//! If a blob has already been seen in the public mempool, then it is often unnecessary to wait for
//! it to arrive on P2P gossip. This PR uses a new JSON-RPC method (`engine_getBlobsV1`) which
//! allows the CL to load the blobs quickly from the EL's blob pool.
//!
//! Once the node fetches the blobs from EL, it then publishes the remaining blobs that it hasn't seen
//! on P2P gossip to the network. From PeerDAS onwards, together with the increase in blob count,
//! broadcasting blobs requires a much higher bandwidth, and is only done by high capacity
//! supernodes.

use crate::blob_verification::{GossipBlobError, GossipVerifiedBlob};
use crate::kzg_utils::blobs_to_data_column_sidecars;
use crate::observed_data_sidecars::DoNotObserve;
use crate::{
    metrics, AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes,
    BlockError,
};
use execution_layer::json_structures::{BlobAndProofV1, BlobAndProofV2};
use execution_layer::Error as ExecutionLayerError;
use metrics::{inc_counter, TryExt};
use ssz_types::FixedVector;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;
use types::blob_sidecar::{BlobSidecarError, FixedBlobSidecarList};
use types::data_column_sidecar::DataColumnSidecarError;
use types::{
    BeaconStateError, Blob, BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecarList, EthSpec,
    FullPayload, Hash256, KzgProofs, SignedBeaconBlock, SignedBeaconBlockHeader, VersionedHash,
};

/// Blobs or data column to be published to the gossip network.
pub enum BlobsOrDataColumns<T: BeaconChainTypes> {
    Blobs(Vec<GossipVerifiedBlob<T, DoNotObserve>>),
    DataColumns(DataColumnSidecarList<T::EthSpec>),
}

/// Result from engine get blobs to be passed onto `DataAvailabilityChecker`.
///
/// The blobs are retrieved from a trusted EL and columns are computed locally, therefore they are
/// considered valid without requiring extra validation.
pub enum EngineGetBlobsOutput<E: EthSpec> {
    Blobs(FixedBlobSidecarList<E>),
    /// A filtered list of custody data columns to be imported into the `DataAvailabilityChecker`.
    CustodyColumns(DataColumnSidecarList<E>),
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
    RequestFailed(ExecutionLayerError),
    RuntimeShutdown,
}

/// Fetches blobs from the EL mempool and processes them. It also broadcasts unseen blobs or
/// data columns (PeerDAS onwards) to the network, using the supplied `publish_fn`.
pub async fn fetch_and_process_engine_blobs<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    custody_columns: HashSet<ColumnIndex>,
    publish_fn: impl Fn(BlobsOrDataColumns<T>) + Send + 'static,
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

    if chain.spec.is_peer_das_enabled_for_epoch(block.epoch()) {
        fetch_and_process_blobs_v2(
            chain,
            block_root,
            block,
            versioned_hashes,
            custody_columns,
            publish_fn,
        )
        .await
    } else {
        fetch_and_process_blobs_v1(chain, block_root, block, versioned_hashes, publish_fn).await
    }
}

async fn fetch_and_process_blobs_v1<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    versioned_hashes: Vec<VersionedHash>,
    publish_fn: impl Fn(BlobsOrDataColumns<T>) + Send + Sized,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    let num_expected_blobs = versioned_hashes.len();
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(FetchEngineBlobError::ExecutionLayerMissing)?;

    metrics::observe(&metrics::BLOBS_FROM_EL_EXPECTED, num_expected_blobs as f64);
    debug!(num_expected_blobs, "Fetching blobs from the EL");
    let response = execution_layer
        .get_blobs_v1(versioned_hashes)
        .await
        .inspect_err(|_| {
            inc_counter(&metrics::BLOBS_FROM_EL_ERROR_TOTAL);
        })
        .map_err(FetchEngineBlobError::RequestFailed)?;

    let num_fetched_blobs = response.iter().filter(|opt| opt.is_some()).count();
    metrics::observe(&metrics::BLOBS_FROM_EL_RECEIVED, num_fetched_blobs as f64);

    if num_fetched_blobs == 0 {
        debug!(num_expected_blobs, "No blobs fetched from the EL");
        inc_counter(&metrics::BLOBS_FROM_EL_MISS_TOTAL);
        return Ok(None);
    } else {
        inc_counter(&metrics::BLOBS_FROM_EL_HIT_TOTAL);
    }

    let (signed_block_header, kzg_commitments_proof) = block
        .signed_block_header_and_kzg_commitments_proof()
        .map_err(FetchEngineBlobError::BeaconStateError)?;

    let fixed_blob_sidecar_list = build_blob_sidecars(
        &block,
        response,
        signed_block_header,
        &kzg_commitments_proof,
        &chain.spec,
    )?;

    // Gossip verify blobs before publishing. This prevents blobs with invalid KZG proofs from
    // the EL making it into the data availability checker. We do not immediately add these
    // blobs to the observed blobs/columns cache because we want to allow blobs/columns to arrive on gossip
    // and be accepted (and propagated) while we are waiting to publish. Just before publishing
    // we will observe the blobs/columns and only proceed with publishing if they are not yet seen.
    let blobs_to_import_and_publish = fixed_blob_sidecar_list
        .iter()
        .filter_map(|opt_blob| {
            let blob = opt_blob.as_ref()?;
            match GossipVerifiedBlob::<T, DoNotObserve>::new(blob.clone(), blob.index, &chain) {
                Ok(verified) => Some(Ok(verified)),
                // Ignore already seen blobs.
                Err(GossipBlobError::RepeatBlob { .. }) => None,
                Err(e) => Some(Err(e)),
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(FetchEngineBlobError::GossipBlob)?;

    if !blobs_to_import_and_publish.is_empty() {
        publish_fn(BlobsOrDataColumns::Blobs(blobs_to_import_and_publish));
    }

    debug!(num_fetched_blobs, "Processing engine blobs");

    let availability_processing_status = chain
        .process_engine_blobs(
            block.slot(),
            block_root,
            EngineGetBlobsOutput::Blobs(fixed_blob_sidecar_list.clone()),
        )
        .await
        .map_err(FetchEngineBlobError::BlobProcessingError)?;

    Ok(Some(availability_processing_status))
}

async fn fetch_and_process_blobs_v2<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    versioned_hashes: Vec<VersionedHash>,
    custody_columns_indices: HashSet<ColumnIndex>,
    publish_fn: impl Fn(BlobsOrDataColumns<T>) + Send + 'static,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    let num_expected_blobs = versioned_hashes.len();
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(FetchEngineBlobError::ExecutionLayerMissing)?;

    metrics::observe(&metrics::BLOBS_FROM_EL_EXPECTED, num_expected_blobs as f64);
    debug!(num_expected_blobs, "Fetching blobs from the EL");
    let response = execution_layer
        .get_blobs_v2(versioned_hashes)
        .await
        .inspect_err(|_| {
            inc_counter(&metrics::BLOBS_FROM_EL_ERROR_TOTAL);
        })
        .map_err(FetchEngineBlobError::RequestFailed)?;

    let (blobs, proofs): (Vec<_>, Vec<_>) = response
        .into_iter()
        .filter_map(|blob_and_proof_opt| {
            blob_and_proof_opt.map(|blob_and_proof| {
                let BlobAndProofV2 { blob, proofs } = blob_and_proof;
                (blob, proofs)
            })
        })
        .unzip();

    let num_fetched_blobs = blobs.len();
    metrics::observe(&metrics::BLOBS_FROM_EL_RECEIVED, num_fetched_blobs as f64);

    // Partial blobs response isn't useful for PeerDAS, so we don't bother building and publishing data columns.
    if num_fetched_blobs != num_expected_blobs {
        debug!(
            info = "Unable to compute data columns",
            num_fetched_blobs, num_expected_blobs, "Not all blobs fetched from the EL"
        );
        inc_counter(&metrics::BLOBS_FROM_EL_MISS_TOTAL);
        return Ok(None);
    } else {
        inc_counter(&metrics::BLOBS_FROM_EL_HIT_TOTAL);
    }

    if chain
        .canonical_head
        .fork_choice_read_lock()
        .contains_block(&block_root)
    {
        // Avoid computing columns if block has already been imported.
        debug!(
            info = "block has already been imported",
            "Ignoring EL blobs response"
        );
        return Ok(None);
    }

    let custody_columns = compute_and_publish_data_columns(
        &chain,
        block.clone(),
        blobs,
        proofs,
        custody_columns_indices,
        publish_fn,
    )
    .await?;

    debug!(num_fetched_blobs, "Processing engine blobs");

    let availability_processing_status = chain
        .process_engine_blobs(
            block.slot(),
            block_root,
            EngineGetBlobsOutput::CustodyColumns(custody_columns),
        )
        .await
        .map_err(FetchEngineBlobError::BlobProcessingError)?;

    Ok(Some(availability_processing_status))
}

/// Offload the data column computation to a blocking task to avoid holding up the async runtime.
async fn compute_and_publish_data_columns<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    blobs: Vec<Blob<T::EthSpec>>,
    proofs: Vec<KzgProofs<T::EthSpec>>,
    custody_columns_indices: HashSet<ColumnIndex>,
    publish_fn: impl Fn(BlobsOrDataColumns<T>) + Send + 'static,
) -> Result<DataColumnSidecarList<T::EthSpec>, FetchEngineBlobError> {
    let chain_cloned = chain.clone();
    chain
        .spawn_blocking_handle(
            move || {
                let mut timer = metrics::start_timer_vec(
                    &metrics::DATA_COLUMN_SIDECAR_COMPUTATION,
                    &[&blobs.len().to_string()],
                );

                let blob_refs = blobs.iter().collect::<Vec<_>>();
                let cell_proofs = proofs.into_iter().flatten().collect();
                let data_columns_result = blobs_to_data_column_sidecars(
                    &blob_refs,
                    cell_proofs,
                    &block,
                    &chain_cloned.kzg,
                    &chain_cloned.spec,
                )
                .discard_timer_on_break(&mut timer);
                drop(timer);

                // This filtering ensures we only import and publish the custody columns.
                // `DataAvailabilityChecker` requires a strict match on custody columns count to
                // consider a block available.
                let custody_columns = data_columns_result
                    .map(|mut data_columns| {
                        data_columns.retain(|col| custody_columns_indices.contains(&col.index));
                        data_columns
                    })
                    .map_err(FetchEngineBlobError::DataColumnSidecarError)?;

                publish_fn(BlobsOrDataColumns::DataColumns(custody_columns.clone()));
                Ok(custody_columns)
            },
            "compute_and_publish_data_columns",
        )
        .await
        .map_err(|e| FetchEngineBlobError::BeaconChainError(Box::new(e)))
        .and_then(|r| r)
}

fn build_blob_sidecars<E: EthSpec>(
    block: &Arc<SignedBeaconBlock<E, FullPayload<E>>>,
    response: Vec<Option<BlobAndProofV1<E>>>,
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitments_inclusion_proof: &FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
    spec: &ChainSpec,
) -> Result<FixedBlobSidecarList<E>, FetchEngineBlobError> {
    let epoch = block.epoch();
    let mut fixed_blob_sidecar_list =
        FixedBlobSidecarList::default(spec.max_blobs_per_block(epoch) as usize);
    for (index, blob_and_proof) in response
        .into_iter()
        .enumerate()
        .filter_map(|(i, opt_blob)| Some((i, opt_blob?)))
    {
        match BlobSidecar::new_with_existing_proof(
            index,
            blob_and_proof.blob,
            block,
            signed_block_header.clone(),
            kzg_commitments_inclusion_proof,
            blob_and_proof.proof,
        ) {
            Ok(blob) => {
                if let Some(blob_mut) = fixed_blob_sidecar_list.get_mut(index) {
                    *blob_mut = Some(Arc::new(blob));
                } else {
                    return Err(FetchEngineBlobError::InternalError(format!(
                        "Blobs from EL contains blob with invalid index {index}"
                    )));
                }
            }
            Err(e) => {
                return Err(FetchEngineBlobError::BlobSidecarError(e));
            }
        }
    }
    Ok(fixed_blob_sidecar_list)
}
