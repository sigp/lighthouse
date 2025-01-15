use crate::sync::manager::BlockProcessType;
use crate::sync::SamplingId;
use crate::{service::NetworkMessage, sync::manager::SyncMessage};
use beacon_chain::blob_verification::{GossipBlobError, GossipVerifiedBlob};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_column_verification::{observe_gossip_data_column, GossipDataColumnError};
use beacon_chain::fetch_blobs::{
    fetch_and_process_engine_blobs, BlobsOrDataColumns, FetchEngineBlobError,
};
use beacon_chain::observed_data_sidecars::DoNotObserve;
use beacon_chain::{
    builder::Witness, eth1_chain::CachingEth1Backend, AvailabilityProcessingStatus, BeaconChain,
    BeaconChainTypes, BlockError, NotifyExecutionLayer,
};
use beacon_processor::{
    work_reprocessing_queue::ReprocessQueueMessage, BeaconProcessorChannels, BeaconProcessorSend,
    DuplicateCache, GossipAggregatePackage, GossipAttestationPackage, Work,
    WorkEvent as BeaconWorkEvent,
};
use lighthouse_network::discovery::ConnectionId;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, BlobsByRootRequest, DataColumnsByRangeRequest, DataColumnsByRootRequest,
    LightClientUpdatesByRangeRequest,
};
use lighthouse_network::rpc::{RequestId, SubstreamId};
use lighthouse_network::{
    rpc::{BlocksByRangeRequest, BlocksByRootRequest, LightClientBootstrapRequest, StatusMessage},
    Client, MessageId, NetworkGlobals, PeerId, PubsubMessage,
};
use rand::prelude::SliceRandom;
use slog::{debug, error, trace, warn, Logger};
use slot_clock::ManualSlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::MemoryStore;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::{self, error::TrySendError};
use types::*;

pub use sync_methods::ChainSegmentProcessId;
use types::blob_sidecar::FixedBlobSidecarList;

pub type Error<T> = TrySendError<BeaconWorkEvent<T>>;

mod gossip_methods;
mod rpc_methods;
mod sync_methods;
mod tests;

pub(crate) const FUTURE_SLOT_TOLERANCE: u64 = 1;

/// Defines if and where we will store the SSZ files of invalid blocks.
#[derive(Clone)]
pub enum InvalidBlockStorage {
    Enabled(PathBuf),
    Disabled,
}

/// Provides an interface to a `BeaconProcessor` running in some other thread.
/// The wider `networking` crate should use this struct to interface with the
/// beacon processor.
pub struct NetworkBeaconProcessor<T: BeaconChainTypes> {
    pub beacon_processor_send: BeaconProcessorSend<T::EthSpec>,
    pub duplicate_cache: DuplicateCache,
    pub chain: Arc<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub reprocess_tx: mpsc::Sender<ReprocessQueueMessage>,
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub invalid_block_storage: InvalidBlockStorage,
    pub executor: TaskExecutor,
    pub log: Logger,
}

// Publish blobs in batches of exponentially increasing size.
const BLOB_PUBLICATION_EXP_FACTOR: usize = 2;

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    fn try_send(&self, event: BeaconWorkEvent<T::EthSpec>) -> Result<(), Error<T::EthSpec>> {
        self.beacon_processor_send
            .try_send(event)
            .map_err(Into::into)
    }

    /// Create a new `Work` event for some unaggregated attestation.
    pub fn send_unaggregated_attestation(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Attestation<T::EthSpec>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        // Define a closure for processing individual attestations.
        let processor = self.clone();
        let process_individual = move |package: GossipAttestationPackage<T::EthSpec>| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_attestation(
                package.message_id,
                package.peer_id,
                package.attestation,
                package.subnet_id,
                package.should_import,
                Some(reprocess_tx),
                package.seen_timestamp,
            )
        };

        // Define a closure for processing batches of attestations.
        let processor = self.clone();
        let process_batch = move |attestations| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_attestation_batch(attestations, Some(reprocess_tx))
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipAttestation {
                attestation: Box::new(GossipAttestationPackage {
                    message_id,
                    peer_id,
                    attestation: Box::new(attestation),
                    subnet_id,
                    should_import,
                    seen_timestamp,
                }),
                process_individual: Box::new(process_individual),
                process_batch: Box::new(process_batch),
            },
        })
    }

    /// Create a new `Work` event for some aggregated attestation.
    pub fn send_aggregated_attestation(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        // Define a closure for processing individual attestations.
        let processor = self.clone();
        let process_individual = move |package: GossipAggregatePackage<T::EthSpec>| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_aggregate(
                package.message_id,
                package.peer_id,
                package.aggregate,
                Some(reprocess_tx),
                package.seen_timestamp,
            )
        };

        // Define a closure for processing batches of attestations.
        let processor = self.clone();
        let process_batch = move |aggregates| {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_aggregate_batch(aggregates, Some(reprocess_tx))
        };

        let beacon_block_root = aggregate.message().aggregate().data().beacon_block_root;
        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipAggregate {
                aggregate: Box::new(GossipAggregatePackage {
                    message_id,
                    peer_id,
                    aggregate: Box::new(aggregate),
                    beacon_block_root,
                    seen_timestamp,
                }),
                process_individual: Box::new(process_individual),
                process_batch: Box::new(process_batch),
            },
        })
    }

    /// Create a new `Work` event for some block.
    pub fn send_gossip_beacon_block(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            let reprocess_tx = processor.reprocess_tx.clone();
            let invalid_block_storage = processor.invalid_block_storage.clone();
            let duplicate_cache = processor.duplicate_cache.clone();
            processor
                .process_gossip_block(
                    message_id,
                    peer_id,
                    peer_client,
                    block,
                    reprocess_tx,
                    duplicate_cache,
                    invalid_block_storage,
                    seen_timestamp,
                )
                .await
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipBlock(Box::pin(process_fn)),
        })
    }

    /// Create a new `Work` event for some blob sidecar.
    pub fn send_gossip_blob_sidecar(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        blob_index: u64,
        blob_sidecar: Arc<BlobSidecar<T::EthSpec>>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .process_gossip_blob(
                    message_id,
                    peer_id,
                    peer_client,
                    blob_index,
                    blob_sidecar,
                    seen_timestamp,
                )
                .await
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipBlobSidecar(Box::pin(process_fn)),
        })
    }

    /// Create a new `Work` event for some data column sidecar.
    pub fn send_gossip_data_column_sidecar(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        subnet_id: DataColumnSubnetId,
        column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .process_gossip_data_column_sidecar(
                    message_id,
                    peer_id,
                    peer_client,
                    subnet_id,
                    column_sidecar,
                    seen_timestamp,
                )
                .await
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipDataColumnSidecar(Box::pin(process_fn)),
        })
    }

    /// Create a new `Work` event for some sync committee signature.
    pub fn send_gossip_sync_signature(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        sync_signature: SyncCommitteeMessage,
        subnet_id: SyncSubnetId,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_sync_committee_signature(
                message_id,
                peer_id,
                sync_signature,
                subnet_id,
                seen_timestamp,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipSyncSignature(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some sync committee contribution.
    pub fn send_gossip_sync_contribution(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        sync_contribution: SignedContributionAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_sync_committee_contribution(
                message_id,
                peer_id,
                sync_contribution,
                seen_timestamp,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipSyncContribution(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some exit.
    pub fn send_gossip_voluntary_exit(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.process_gossip_voluntary_exit(message_id, peer_id, *voluntary_exit);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipVoluntaryExit(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some proposer slashing.
    pub fn send_gossip_proposer_slashing(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_proposer_slashing(message_id, peer_id, *proposer_slashing)
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipProposerSlashing(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some light client finality update.
    pub fn send_gossip_light_client_finality_update(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        light_client_finality_update: LightClientFinalityUpdate<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_finality_update(
                message_id,
                peer_id,
                light_client_finality_update,
                seen_timestamp,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipLightClientFinalityUpdate(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some light client optimistic update.
    pub fn send_gossip_light_client_optimistic_update(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        light_client_optimistic_update: LightClientOptimisticUpdate<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            let reprocess_tx = processor.reprocess_tx.clone();
            processor.process_gossip_optimistic_update(
                message_id,
                peer_id,
                light_client_optimistic_update,
                Some(reprocess_tx),
                seen_timestamp,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipLightClientOptimisticUpdate(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some attester slashing.
    pub fn send_gossip_attester_slashing(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<T::EthSpec>>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_attester_slashing(message_id, peer_id, *attester_slashing)
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipAttesterSlashing(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some BLS to execution change.
    pub fn send_gossip_bls_to_execution_change(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        bls_to_execution_change: Box<SignedBlsToExecutionChange>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_bls_to_execution_change(
                message_id,
                peer_id,
                *bls_to_execution_change,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipBlsToExecutionChange(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some block, where the result from computation (if any) is
    /// sent to the other side of `result_tx`.
    pub fn send_rpc_beacon_block(
        self: &Arc<Self>,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), Error<T::EthSpec>> {
        let process_fn = self.clone().generate_rpc_beacon_block_process_fn(
            block_root,
            block,
            seen_timestamp,
            process_type,
        );
        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::RpcBlock { process_fn },
        })
    }

    /// Create a new `Work` event for some blobs, where the result from computation (if any) is
    /// sent to the other side of `result_tx`.
    pub fn send_rpc_blobs(
        self: &Arc<Self>,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), Error<T::EthSpec>> {
        let blob_count = blobs.iter().filter(|b| b.is_some()).count();
        if blob_count == 0 {
            return Ok(());
        }
        let process_fn = self.clone().generate_rpc_blobs_process_fn(
            block_root,
            blobs,
            seen_timestamp,
            process_type,
        );
        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::RpcBlobs { process_fn },
        })
    }

    /// Create a new `Work` event for some custody columns. `process_rpc_custody_columns` reports
    /// the result back to sync.
    pub fn send_rpc_custody_columns(
        self: &Arc<Self>,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), Error<T::EthSpec>> {
        let s = self.clone();
        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::RpcCustodyColumn(Box::pin(async move {
                s.process_rpc_custody_columns(
                    block_root,
                    custody_columns,
                    seen_timestamp,
                    process_type,
                )
                .await;
            })),
        })
    }

    /// Create a new `Work` event for some sampling columns, and reports the verification result
    /// back to sync.
    pub fn send_rpc_validate_data_columns(
        self: &Arc<Self>,
        block_root: Hash256,
        data_columns: Vec<Arc<DataColumnSidecar<T::EthSpec>>>,
        seen_timestamp: Duration,
        id: SamplingId,
    ) -> Result<(), Error<T::EthSpec>> {
        let s = self.clone();
        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::RpcVerifyDataColumn(Box::pin(async move {
                let result = s
                    .clone()
                    .validate_rpc_data_columns(block_root, data_columns, seen_timestamp)
                    .await;
                // Sync handles these results
                s.send_sync_message(SyncMessage::SampleVerified { id, result });
            })),
        })
    }

    /// Create a new `Work` event with a block sampling completed result
    pub fn send_sampling_completed(
        self: &Arc<Self>,
        block_root: Hash256,
    ) -> Result<(), Error<T::EthSpec>> {
        let nbp = self.clone();
        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::SamplingResult(Box::pin(async move {
                nbp.process_sampling_completed(block_root).await;
            })),
        })
    }

    /// Create a new work event to import `blocks` as a beacon chain segment.
    pub fn send_chain_segment(
        self: &Arc<Self>,
        process_id: ChainSegmentProcessId,
        blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> Result<(), Error<T::EthSpec>> {
        let is_backfill = matches!(&process_id, ChainSegmentProcessId::BackSyncBatchId { .. });
        let processor = self.clone();
        let process_fn = async move {
            let notify_execution_layer = if processor
                .network_globals
                .sync_state
                .read()
                .is_syncing_finalized()
            {
                NotifyExecutionLayer::No
            } else {
                NotifyExecutionLayer::Yes
            };
            processor
                .process_chain_segment(process_id, blocks, notify_execution_layer)
                .await;
        };
        let process_fn = Box::pin(process_fn);

        // Back-sync batches are dispatched with a different `Work` variant so
        // they can be rate-limited.
        let work = if is_backfill {
            Work::ChainSegmentBackfill(process_fn)
        } else {
            Work::ChainSegment(process_fn)
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work,
        })
    }

    /// Create a new work event to process `StatusMessage`s from the RPC network.
    pub fn send_status_message(
        self: &Arc<Self>,
        peer_id: PeerId,
        message: StatusMessage,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || processor.process_status(peer_id, message);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::Status(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `BlocksByRangeRequest`s from the RPC network.
    pub fn send_blocks_by_range_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: BlocksByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .handle_blocks_by_range_request(
                    peer_id,
                    connection_id,
                    substream_id,
                    request_id,
                    request,
                )
                .await;
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRangeRequest(Box::pin(process_fn)),
        })
    }

    /// Create a new work event to process `BlocksByRootRequest`s from the RPC network.
    pub fn send_blocks_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: BlocksByRootRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .handle_blocks_by_root_request(
                    peer_id,
                    connection_id,
                    substream_id,
                    request_id,
                    request,
                )
                .await;
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRootsRequest(Box::pin(process_fn)),
        })
    }

    /// Create a new work event to process `BlobsByRangeRequest`s from the RPC network.
    pub fn send_blobs_by_range_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: BlobsByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_blobs_by_range_request(
                peer_id,
                connection_id,
                substream_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlobsByRangeRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `BlobsByRootRequest`s from the RPC network.
    pub fn send_blobs_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: BlobsByRootRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_blobs_by_root_request(
                peer_id,
                connection_id,
                substream_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlobsByRootsRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `DataColumnsByRootRequest`s from the RPC network.
    pub fn send_data_columns_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: DataColumnsByRootRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_data_columns_by_root_request(
                peer_id,
                connection_id,
                substream_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::DataColumnsByRootsRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `DataColumnsByRange`s from the RPC network.
    pub fn send_data_columns_by_range_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: DataColumnsByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_data_columns_by_range_request(
                peer_id,
                connection_id,
                substream_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::DataColumnsByRangeRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `LightClientBootstrap`s from the RPC network.
    pub fn send_light_client_bootstrap_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: LightClientBootstrapRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_light_client_bootstrap(
                peer_id,
                connection_id,
                substream_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientBootstrapRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process a `LightClientOptimisticUpdate` request from the RPC network.
    pub fn send_light_client_optimistic_update_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_light_client_optimistic_update(
                peer_id,
                connection_id,
                substream_id,
                request_id,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientOptimisticUpdateRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process a `LightClientFinalityUpdate` request from the RPC network.
    pub fn send_light_client_finality_update_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_light_client_finality_update(
                peer_id,
                connection_id,
                substream_id,
                request_id,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientFinalityUpdateRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process a `LightClientUpdatesByRange` request from the RPC network.
    pub fn send_light_client_updates_by_range_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        request_id: RequestId,
        request: LightClientUpdatesByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_light_client_updates_by_range(
                peer_id,
                connection_id,
                substream_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientUpdatesByRangeRequest(Box::new(process_fn)),
        })
    }

    /// Send a message to `sync_tx`.
    ///
    /// Creates a log if there is an internal error.
    pub(crate) fn send_sync_message(&self, message: SyncMessage<T::EthSpec>) {
        self.sync_tx.send(message).unwrap_or_else(|e| {
            debug!(self.log, "Could not send message to the sync service";
                   "error" => %e)
        });
    }

    /// Send a message to `network_tx`.
    ///
    /// Creates a log if there is an internal error.
    fn send_network_message(&self, message: NetworkMessage<T::EthSpec>) {
        self.network_tx.send(message).unwrap_or_else(|e| {
            debug!(self.log, "Could not send message to the network service. Likely shutdown";
                "error" => %e)
        });
    }

    pub async fn fetch_engine_blobs_and_publish(
        self: &Arc<Self>,
        block: Arc<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>>,
        block_root: Hash256,
        publish_blobs: bool,
    ) {
        let self_cloned = self.clone();
        let publish_fn = move |blobs_or_data_column| {
            if publish_blobs {
                match blobs_or_data_column {
                    BlobsOrDataColumns::Blobs(blobs) => {
                        self_cloned.publish_blobs_gradually(blobs, block_root);
                    }
                    BlobsOrDataColumns::DataColumns(columns) => {
                        self_cloned.publish_data_columns_gradually(columns, block_root);
                    }
                };
            }
        };

        match fetch_and_process_engine_blobs(
            self.chain.clone(),
            block_root,
            block.clone(),
            publish_fn,
        )
        .await
        {
            Ok(Some(availability)) => match availability {
                AvailabilityProcessingStatus::Imported(_) => {
                    debug!(
                        self.log,
                        "Block components retrieved from EL";
                        "result" => "imported block and custody columns",
                        "block_root" => %block_root,
                    );
                    self.chain.recompute_head_at_current_slot().await;
                }
                AvailabilityProcessingStatus::MissingComponents(_, _) => {
                    debug!(
                        self.log,
                        "Still missing blobs after engine blobs processed successfully";
                        "block_root" => %block_root,
                    );
                }
            },
            Ok(None) => {
                debug!(
                    self.log,
                    "Fetch blobs completed without import";
                    "block_root" => %block_root,
                );
            }
            Err(FetchEngineBlobError::BlobProcessingError(BlockError::DuplicateFullyImported(
                ..,
            ))) => {
                debug!(
                    self.log,
                    "Fetch blobs duplicate import";
                    "block_root" => %block_root,
                );
            }
            Err(e) => {
                error!(
                    self.log,
                    "Error fetching or processing blobs from EL";
                    "error" => ?e,
                    "block_root" => %block_root,
                );
            }
        }
    }

    /// Attempt to reconstruct all data columns if the following conditions satisfies:
    /// - Our custody requirement is all columns
    /// - We have >= 50% of columns, but not all columns
    ///
    /// Returns `Some(AvailabilityProcessingStatus)` if reconstruction is successfully performed,
    /// otherwise returns `None`.
    async fn attempt_data_column_reconstruction(
        self: &Arc<Self>,
        block_root: Hash256,
    ) -> Option<AvailabilityProcessingStatus> {
        let result = self.chain.reconstruct_data_columns(block_root).await;
        match result {
            Ok(Some((availability_processing_status, data_columns_to_publish))) => {
                self.publish_data_columns_gradually(data_columns_to_publish, block_root);
                match &availability_processing_status {
                    AvailabilityProcessingStatus::Imported(hash) => {
                        debug!(
                            self.log,
                            "Block components available via reconstruction";
                            "result" => "imported block and custody columns",
                            "block_hash" => %hash,
                        );
                        self.chain.recompute_head_at_current_slot().await;
                    }
                    AvailabilityProcessingStatus::MissingComponents(_, _) => {
                        debug!(
                            self.log,
                            "Block components still missing block after reconstruction";
                            "result" => "imported all custody columns",
                            "block_hash" => %block_root,
                        );
                    }
                }

                Some(availability_processing_status)
            }
            Ok(None) => {
                // reason is tracked via the `KZG_DATA_COLUMN_RECONSTRUCTION_INCOMPLETE_TOTAL` metric
                trace!(
                    self.log,
                    "Reconstruction not required for block";
                    "block_hash" => %block_root,
                );
                None
            }
            Err(e) => {
                error!(
                    self.log,
                    "Error during data column reconstruction";
                    "block_root" => %block_root,
                    "error" => ?e
                );
                None
            }
        }
    }

    /// This function gradually publishes blobs to the network in randomised batches.
    ///
    /// This is an optimisation to reduce outbound bandwidth and ensures each blob is published
    /// by some nodes on the network as soon as possible. Our hope is that some blobs arrive from
    /// other nodes in the meantime, obviating the need for us to publish them. If no other
    /// publisher exists for a blob, it will eventually get published here.
    fn publish_blobs_gradually(
        self: &Arc<Self>,
        mut blobs: Vec<GossipVerifiedBlob<T, DoNotObserve>>,
        block_root: Hash256,
    ) {
        let self_clone = self.clone();

        self.executor.spawn(
            async move {
                let chain = self_clone.chain.clone();
                let log = self_clone.chain.logger();
                let publish_fn = |blobs: Vec<Arc<BlobSidecar<T::EthSpec>>>| {
                    self_clone.send_network_message(NetworkMessage::Publish {
                        messages: blobs
                            .into_iter()
                            .map(|blob| PubsubMessage::BlobSidecar(Box::new((blob.index, blob))))
                            .collect(),
                    });
                };

                // Permute the blobs and split them into batches.
                // The hope is that we won't need to publish some blobs because we will receive them
                // on gossip from other nodes.
                blobs.shuffle(&mut rand::thread_rng());

                let blob_publication_batch_interval = chain.config.blob_publication_batch_interval;
                let mut publish_count = 0usize;
                let blob_count = blobs.len();
                let mut blobs_iter = blobs.into_iter().peekable();
                let mut batch_size = 1usize;

                while blobs_iter.peek().is_some() {
                    let batch = blobs_iter.by_ref().take(batch_size);
                    let publishable = batch
                        .filter_map(|unobserved| match unobserved.observe(&chain) {
                            Ok(observed) => Some(observed.clone_blob()),
                            Err(GossipBlobError::RepeatBlob { .. }) => None,
                            Err(e) => {
                                warn!(
                                    log,
                                    "Previously verified blob is invalid";
                                    "error" => ?e
                                );
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    if !publishable.is_empty() {
                        debug!(
                            log,
                            "Publishing blob batch";
                            "publish_count" => publishable.len(),
                            "block_root" => ?block_root,
                        );
                        publish_count += publishable.len();
                        publish_fn(publishable);
                    }

                    tokio::time::sleep(blob_publication_batch_interval).await;
                    batch_size *= BLOB_PUBLICATION_EXP_FACTOR;
                }

                debug!(
                    log,
                    "Batch blob publication complete";
                    "batch_interval" => blob_publication_batch_interval.as_millis(),
                    "blob_count" => blob_count,
                    "published_count" => publish_count,
                    "block_root" => ?block_root,
                )
            },
            "gradual_blob_publication",
        );
    }

    /// This function gradually publishes data columns to the network in randomised batches.
    ///
    /// This is an optimisation to reduce outbound bandwidth and ensures each column is published
    /// by some nodes on the network as soon as possible. Our hope is that some columns arrive from
    /// other supernodes in the meantime, obviating the need for us to publish them. If no other
    /// publisher exists for a column, it will eventually get published here.
    fn publish_data_columns_gradually(
        self: &Arc<Self>,
        mut data_columns_to_publish: DataColumnSidecarList<T::EthSpec>,
        block_root: Hash256,
    ) {
        let self_clone = self.clone();

        self.executor.spawn(
            async move {
                let chain = self_clone.chain.clone();
                let log = self_clone.chain.logger();
                let publish_fn = |columns: DataColumnSidecarList<T::EthSpec>| {
                    self_clone.send_network_message(NetworkMessage::Publish {
                        messages: columns
                            .into_iter()
                            .map(|d| {
                                let subnet = DataColumnSubnetId::from_column_index::<T::EthSpec>(
                                    d.index as usize,
                                    &chain.spec,
                                );
                                PubsubMessage::DataColumnSidecar(Box::new((subnet, d)))
                            })
                            .collect(),
                    });
                };

                // If this node is a super node, permute the columns and split them into batches.
                // The hope is that we won't need to publish some columns because we will receive them
                // on gossip from other supernodes.
                data_columns_to_publish.shuffle(&mut rand::thread_rng());

                let blob_publication_batch_interval = chain.config.blob_publication_batch_interval;
                let blob_publication_batches = chain.config.blob_publication_batches;
                let batch_size = chain.spec.number_of_columns / blob_publication_batches;
                let mut publish_count = 0usize;

                for batch in data_columns_to_publish.chunks(batch_size) {
                    let publishable = batch
                        .iter()
                        .filter_map(|col| match observe_gossip_data_column(col, &chain) {
                            Ok(()) => Some(col.clone()),
                            Err(GossipDataColumnError::PriorKnown { .. }) => None,
                            Err(e) => {
                                warn!(
                                    log,
                                    "Previously verified data column is invalid";
                                    "error" => ?e
                                );
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    if !publishable.is_empty() {
                        debug!(
                            log,
                            "Publishing data column batch";
                            "publish_count" => publishable.len(),
                            "block_root" => ?block_root,
                        );
                        publish_count += publishable.len();
                        publish_fn(publishable);
                    }

                    tokio::time::sleep(blob_publication_batch_interval).await;
                }

                debug!(
                    log,
                    "Batch data column publishing complete";
                    "batch_size" => batch_size,
                    "batch_interval" => blob_publication_batch_interval.as_millis(),
                    "data_columns_to_publish_count" => data_columns_to_publish.len(),
                    "published_count" => publish_count,
                    "block_root" => ?block_root,
                )
            },
            "gradual_data_column_publication",
        );
    }
}

type TestBeaconChainType<E> =
    Witness<ManualSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

impl<E: EthSpec> NetworkBeaconProcessor<TestBeaconChainType<E>> {
    // Instantiates a mostly non-functional version of `Self` and returns the
    // event receiver that would normally go to the beacon processor. This is
    // useful for testing that messages are actually being sent to the beacon
    // processor (but not much else).
    pub fn null_for_testing(
        network_globals: Arc<NetworkGlobals<E>>,
        sync_tx: UnboundedSender<SyncMessage<E>>,
        chain: Arc<BeaconChain<TestBeaconChainType<E>>>,
        executor: TaskExecutor,
        log: Logger,
    ) -> (Self, mpsc::Receiver<BeaconWorkEvent<E>>) {
        let BeaconProcessorChannels {
            beacon_processor_tx,
            beacon_processor_rx,
            work_reprocessing_tx,
            work_reprocessing_rx: _work_reprocessing_rx,
        } = <_>::default();

        let (network_tx, _network_rx) = mpsc::unbounded_channel();

        let network_beacon_processor = Self {
            beacon_processor_send: beacon_processor_tx,
            duplicate_cache: DuplicateCache::default(),
            chain,
            network_tx,
            sync_tx,
            reprocess_tx: work_reprocessing_tx,
            network_globals,
            invalid_block_storage: InvalidBlockStorage::Disabled,
            executor,
            log,
        };

        (network_beacon_processor, beacon_processor_rx)
    }
}
