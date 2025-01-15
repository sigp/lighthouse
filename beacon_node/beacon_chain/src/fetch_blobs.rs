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
use crate::{metrics, AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes, BlockError};
use execution_layer::json_structures::BlobAndProofV1;
use execution_layer::Error as ExecutionLayerError;
use metrics::{inc_counter, inc_counter_by, TryExt};
use slog::{debug, error, o, Logger};
use ssz_types::FixedVector;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use types::blob_sidecar::{BlobSidecarError, FixedBlobSidecarList};
use types::{
    BeaconStateError, BlobSidecar, DataColumnSidecar, DataColumnSidecarList, EthSpec, FullPayload,
    Hash256, SignedBeaconBlock, SignedBeaconBlockHeader,
};

pub enum BlobsOrDataColumns<T: BeaconChainTypes> {
    Blobs(Vec<GossipVerifiedBlob<T, DoNotObserve>>),
    DataColumns(DataColumnSidecarList<T::EthSpec>),
}

#[derive(Debug)]
pub enum FetchEngineBlobError {
    BeaconStateError(BeaconStateError),
    BlobProcessingError(BlockError),
    BlobSidecarError(BlobSidecarError),
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
    publish_fn: impl Fn(BlobsOrDataColumns<T>) + Send + 'static,
) -> Result<Option<AvailabilityProcessingStatus>, FetchEngineBlobError> {
    let block_root_str = format!("{:?}", block_root);
    let log = chain
        .log
        .new(o!("service" => "fetch_engine_blobs", "block_root" => block_root_str));

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
        debug!(
            log,
            "Fetch blobs not triggered - none required";
        );
        return Ok(None);
    };

    let num_expected_blobs = versioned_hashes.len();

    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(FetchEngineBlobError::ExecutionLayerMissing)?;

    debug!(
        log,
        "Fetching blobs from the EL";
        "num_expected_blobs" => num_expected_blobs,
    );
    let response = execution_layer
        .get_blobs(versioned_hashes)
        .await
        .map_err(FetchEngineBlobError::RequestFailed)?;

    if response.is_empty() {
        debug!(
           log,
            "No blobs fetched from the EL";
            "num_expected_blobs" => num_expected_blobs,
        );
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
    )?;

    let num_fetched_blobs = fixed_blob_sidecar_list
        .iter()
        .filter(|b| b.is_some())
        .count();

    inc_counter_by(
        &metrics::BLOBS_FROM_EL_EXPECTED_TOTAL,
        num_expected_blobs as u64,
    );
    inc_counter_by(
        &metrics::BLOBS_FROM_EL_RECEIVED_TOTAL,
        num_fetched_blobs as u64,
    );

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

    let peer_das_enabled = chain.spec.is_peer_das_enabled_for_epoch(block.epoch());

    let data_columns_receiver_opt = if peer_das_enabled {
        // Partial blobs response isn't useful for PeerDAS, so we don't bother building and publishing data columns.
        if num_fetched_blobs != num_expected_blobs {
            debug!(
                log,
                "Not all blobs fetched from the EL";
                "info" => "Unable to compute data columns",
                "num_fetched_blobs" => num_fetched_blobs,
                "num_expected_blobs" => num_expected_blobs,
            );
            return Ok(None);
        }

        let data_columns_receiver = spawn_compute_and_publish_data_columns_task(
            &chain,
            block.clone(),
            fixed_blob_sidecar_list.clone(),
            publish_fn,
            log.clone(),
        );

        Some(data_columns_receiver)
    } else {
        if !blobs_to_import_and_publish.is_empty() {
            publish_fn(BlobsOrDataColumns::Blobs(blobs_to_import_and_publish));
        }

        None
    };

    debug!(
        log,
        "Processing engine blobs";
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
        .map_err(FetchEngineBlobError::BlobProcessingError)?;

    Ok(Some(availability_processing_status))
}

/// Spawn a blocking task here for long computation tasks, so it doesn't block processing, and it
/// allows blobs / data columns to propagate without waiting for processing.
///
/// An `mpsc::Sender` is then used to send the produced data columns to the `beacon_chain` for it
/// to be persisted, **after** the block is made attestable.
///
/// The reason for doing this is to make the block available and attestable as soon as possible,
/// while maintaining the invariant that block and data columns are persisted atomically.
fn spawn_compute_and_publish_data_columns_task<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
    blobs: FixedBlobSidecarList<T::EthSpec>,
    publish_fn: impl Fn(BlobsOrDataColumns<T>) + Send + 'static,
    log: Logger,
) -> Receiver<Vec<Arc<DataColumnSidecar<T::EthSpec>>>> {
    let chain_cloned = chain.clone();
    let (data_columns_sender, data_columns_receiver) = tokio::sync::mpsc::channel(1);

    chain.task_executor.spawn_blocking(
        move || {
            let mut timer = metrics::start_timer_vec(
                &metrics::DATA_COLUMN_SIDECAR_COMPUTATION,
                &[&blobs.len().to_string()],
            );
            let blob_refs = blobs
                .iter()
                .filter_map(|b| b.as_ref().map(|b| &b.blob))
                .collect::<Vec<_>>();
            let data_columns_result = blobs_to_data_column_sidecars(
                &blob_refs,
                &block,
                &chain_cloned.kzg,
                &chain_cloned.spec,
            )
            .discard_timer_on_break(&mut timer);
            drop(timer);

            let all_data_columns = match data_columns_result {
                Ok(d) => d,
                Err(e) => {
                    error!(
                        log,
                        "Failed to build data column sidecars from blobs";
                        "error" => ?e
                    );
                    return;
                }
            };

            if let Err(e) = data_columns_sender.try_send(all_data_columns.clone()) {
                error!(log, "Failed to send computed data columns"; "error" => ?e);
            };

            // Check indices from cache before sending the columns, to make sure we don't
            // publish components already seen on gossip.
            let is_supernode = chain_cloned.data_availability_checker.is_supernode();

            // At the moment non supernodes are not required to publish any columns.
            // TODO(das): we could experiment with having full nodes publish their custodied
            // columns here.
            if !is_supernode {
                return;
            }

            publish_fn(BlobsOrDataColumns::DataColumns(all_data_columns));
        },
        "compute_and_publish_data_columns",
    );

    data_columns_receiver
}

fn build_blob_sidecars<E: EthSpec>(
    block: &Arc<SignedBeaconBlock<E, FullPayload<E>>>,
    response: Vec<Option<BlobAndProofV1<E>>>,
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitments_inclusion_proof: &FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
) -> Result<FixedBlobSidecarList<E>, FetchEngineBlobError> {
    let mut fixed_blob_sidecar_list = FixedBlobSidecarList::default();
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
