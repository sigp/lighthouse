use crate::sync::manager::BlockProcessType;
use crate::{service::NetworkMessage, sync::manager::SyncMessage};
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::block_verification_types::RangeSyncBlock;
use beacon_chain::data_column_verification::{
    GossipDataColumnError, KzgVerifiedCustodyDataColumn, observe_gossip_data_column,
};
use beacon_chain::fetch_blobs::{FetchEngineBlobError, fetch_and_process_engine_blobs};
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes, BlockError};
use beacon_processor::{
    BeaconProcessorSend, DuplicateCache, GossipAggregatePackage, GossipAttestationPackage, Work,
    WorkEvent as BeaconWorkEvent,
};
use lighthouse_network::rpc::InboundRequestId;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, BlobsByRootRequest, BlocksByHeadRequest, DataColumnsByRangeRequest,
    DataColumnsByRootRequest, LightClientUpdatesByRangeRequest, PayloadEnvelopesByRangeRequest,
    PayloadEnvelopesByRootRequest,
};
use lighthouse_network::service::api_types::CustodyBackfillBatchId;
use lighthouse_network::{
    Client, GossipTopic, MessageId, NetworkConfig, NetworkGlobals, PeerId, PubsubMessage,
    rpc::{BlocksByRangeRequest, BlocksByRootRequest, LightClientBootstrapRequest, StatusMessage},
};
use rand::prelude::SliceRandom;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, error, instrument, trace, warn};
use types::*;
use {
    beacon_chain::builder::Witness, beacon_processor::BeaconProcessorChannels,
    slot_clock::ManualSlotClock, store::MemoryStore, tokio::sync::mpsc::UnboundedSender,
};

pub use sync_methods::ChainSegmentProcessId;
use types::data::FixedBlobSidecarList;

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
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub invalid_block_storage: InvalidBlockStorage,
    pub executor: TaskExecutor,
}

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    fn try_send(&self, event: BeaconWorkEvent<T::EthSpec>) -> Result<(), Error<T::EthSpec>> {
        self.beacon_processor_send.try_send(event)
    }

    /// Create a new `Work` event for some unaggregated attestation.
    pub fn send_unaggregated_attestation(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        attestation: SingleAttestation,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        // Define a closure for processing individual attestations.
        let processor = self.clone();
        let process_individual = move |package: GossipAttestationPackage<SingleAttestation>| {
            processor.process_gossip_attestation(
                package.message_id,
                package.peer_id,
                package.attestation,
                package.subnet_id,
                package.should_import,
                true,
                package.seen_timestamp,
            )
        };

        // Define a closure for processing batches of attestations.
        let processor = self.clone();
        let process_batch =
            move |attestations| processor.process_gossip_attestation_batch(attestations, true);

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
            processor.process_gossip_aggregate(
                package.message_id,
                package.peer_id,
                package.aggregate,
                true,
                package.seen_timestamp,
            )
        };

        // Define a closure for processing batches of attestations.
        let processor = self.clone();
        let process_batch =
            move |aggregates| processor.process_gossip_aggregate_batch(aggregates, true);

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
            let invalid_block_storage = processor.invalid_block_storage.clone();
            let duplicate_cache = processor.duplicate_cache.clone();
            processor
                .process_gossip_block(
                    message_id,
                    peer_id,
                    peer_client,
                    block,
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

    /// Create a new `Work` event for some data column sidecar.
    pub fn send_gossip_data_column_sidecar(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
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

    /// Create a new `Work` event for some partial data column sidecar.
    pub fn send_gossip_partial_data_column_sidecar(
        self: &Arc<Self>,
        peer_id: PeerId,
        column_sidecar: Box<PartialDataColumn<T::EthSpec>>,
        seen_timestamp: Duration,
        topic: GossipTopic,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .process_gossip_partial_data_column_sidecar(
                    peer_id,
                    column_sidecar,
                    seen_timestamp,
                    topic,
                )
                .await
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipPartialDataColumnSidecar(Box::pin(process_fn)),
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
            processor.process_gossip_proposer_slashing(message_id, peer_id, *proposer_slashing);
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
            processor.process_gossip_optimistic_update(
                message_id,
                peer_id,
                light_client_optimistic_update,
                true,
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
            processor.process_gossip_attester_slashing(message_id, peer_id, *attester_slashing);
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

    /// Create a new `Work` event for some execution payload envelope.
    pub fn send_gossip_execution_payload(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        execution_payload: Box<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        seen_timestamp: Duration,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .process_gossip_execution_payload_envelope(
                    message_id,
                    peer_id,
                    Arc::new(*execution_payload),
                    seen_timestamp,
                )
                .await
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::GossipExecutionPayload(Box::pin(process_fn)),
        })
    }

    /// Create a new `Work` event for some execution payload bid
    pub fn send_gossip_execution_payload_bid(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        execution_payload_bid: Box<SignedExecutionPayloadBid<T::EthSpec>>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_execution_payload_bid(
                message_id,
                peer_id,
                Arc::new(*execution_payload_bid),
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipExecutionPayloadBid(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some payload attestation
    pub fn send_gossip_payload_attestation(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        payload_attestation_message: Box<PayloadAttestationMessage>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_payload_attestation(
                message_id,
                peer_id,
                payload_attestation_message,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipPayloadAttestation(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some proposer preferences
    pub fn send_gossip_proposer_preferences(
        self: &Arc<Self>,
        message_id: MessageId,
        peer_id: PeerId,
        proposer_preferences: Arc<SignedProposerPreferences>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.process_gossip_proposer_preferences(message_id, peer_id, proposer_preferences)
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipProposerPreferences(Box::new(process_fn)),
        })
    }

    /// Create a new `Work` event for some block, where the result from computation (if any) is
    /// sent to the other side of `result_tx`.
    pub fn send_lookup_beacon_block(
        self: &Arc<Self>,
        block_root: Hash256,
        block: LookupBlock<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), Error<T::EthSpec>> {
        let process_fn = self.clone().generate_lookup_beacon_block_process_fn(
            block_root,
            block,
            seen_timestamp,
            process_type,
        );
        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::RpcBlock {
                process_fn,
                beacon_block_root: block_root,
            },
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

    /// Create a new `Work` event for an RPC-fetched payload envelope. `process_lookup_envelope`
    /// reports the result back to sync.
    pub fn send_lookup_envelope(
        self: &Arc<Self>,
        block_root: Hash256,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), Error<T::EthSpec>> {
        let s = self.clone();
        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::RpcEnvelope(Box::pin(async move {
                s.process_lookup_envelope(block_root, envelope, seen_timestamp, process_type)
                    .await;
            })),
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

    pub fn send_historic_data_columns(
        self: &Arc<Self>,
        batch_id: CustodyBackfillBatchId,
        data_columns: DataColumnSidecarList<T::EthSpec>,
        expected_cgc: u64,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.process_historic_data_columns(batch_id, data_columns, expected_cgc);

        let work = Work::ChainSegmentBackfill(Box::new(process_fn));

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work,
        })
    }

    /// Create a new work event to import `blocks` as a beacon chain segment.
    pub fn send_chain_segment(
        self: &Arc<Self>,
        process_id: ChainSegmentProcessId,
        blocks: Vec<RangeSyncBlock<T::EthSpec>>,
    ) -> Result<(), Error<T::EthSpec>> {
        debug!(blocks = blocks.len(), id = ?process_id, "Batch sending for process");
        let processor = self.clone();

        // Back-sync batches are dispatched with a different `Work` variant so
        // they can be rate-limited.
        let work = match process_id {
            ChainSegmentProcessId::RangeBatchId(chain_id, epoch) => {
                let process_fn = async move {
                    processor.process_chain_segment(process_id, blocks).await;
                };
                Work::ChainSegment {
                    process_fn: Box::pin(process_fn),
                    process_id: (chain_id, epoch.as_u64()),
                }
            }
            ChainSegmentProcessId::BackSyncBatchId(_) => {
                let process_fn =
                    move || processor.process_chain_segment_backfill(process_id, blocks);
                Work::ChainSegmentBackfill(Box::new(process_fn))
            }
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
        inbound_request_id: InboundRequestId, // Use ResponseId here
        request: BlocksByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .handle_blocks_by_range_request(peer_id, inbound_request_id, request)
                .await;
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRangeRequest(Box::pin(process_fn)),
        })
    }

    /// Create a new work event to process `BlocksByHeadRequest`s from the RPC network.
    pub fn send_blocks_by_head_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlocksByHeadRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .handle_blocks_by_head_request(peer_id, inbound_request_id, request)
                .await;
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByHeadRequest(Box::pin(process_fn)),
        })
    }

    /// Create a new work event to process `BlocksByRootRequest`s from the RPC network.
    pub fn send_blocks_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId, // Use ResponseId here
        request: BlocksByRootRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .handle_blocks_by_root_request(peer_id, inbound_request_id, request)
                .await;
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRootsRequest(Box::pin(process_fn)),
        })
    }

    /// Create a new work event to process `PayloadEnvelopesByRootRequest`s from the RPC network.
    pub fn send_payload_envelopes_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId, // Use ResponseId here
        request: PayloadEnvelopesByRootRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .handle_payload_envelopes_by_root_request(peer_id, inbound_request_id, request)
                .await;
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::PayloadEnvelopesByRootRequest(Box::pin(process_fn)),
        })
    }

    /// Create a new work event to process `PayloadEnvelopesByRangeRequest`s from the RPC network.
    pub fn send_payload_envelopes_by_range_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: PayloadEnvelopesByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = async move {
            processor
                .handle_payload_envelopes_by_range_request(peer_id, inbound_request_id, request)
                .await;
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::PayloadEnvelopesByRangeRequest(Box::pin(process_fn)),
        })
    }

    /// Create a new work event to process `BlobsByRangeRequest`s from the RPC network.
    pub fn send_blobs_by_range_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlobsByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.handle_blobs_by_range_request(peer_id, inbound_request_id, request);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlobsByRangeRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `BlobsByRootRequest`s from the RPC network.
    pub fn send_blobs_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlobsByRootRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.handle_blobs_by_root_request(peer_id, inbound_request_id, request);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlobsByRootsRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `DataColumnsByRootRequest`s from the RPC network.
    pub fn send_data_columns_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: DataColumnsByRootRequest<T::EthSpec>,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_data_columns_by_root_request(peer_id, inbound_request_id, request)
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
        inbound_request_id: InboundRequestId,
        request: DataColumnsByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_data_columns_by_range_request(peer_id, inbound_request_id, request)
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
        inbound_request_id: InboundRequestId,
        request: LightClientBootstrapRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.handle_light_client_bootstrap(peer_id, inbound_request_id, request);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientBootstrapRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process a `LightClientOptimisticUpdate` request from the RPC network.
    pub fn send_light_client_optimistic_update_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.handle_light_client_optimistic_update(peer_id, inbound_request_id);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientOptimisticUpdateRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process a `LightClientFinalityUpdate` request from the RPC network.
    pub fn send_light_client_finality_update_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.handle_light_client_finality_update(peer_id, inbound_request_id);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientFinalityUpdateRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process a `LightClientUpdatesByRange` request from the RPC network.
    pub fn send_light_client_updates_by_range_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: LightClientUpdatesByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move || {
            processor.handle_light_client_updates_by_range(peer_id, inbound_request_id, request)
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
        self.sync_tx
            .send(message)
            .unwrap_or_else(|e| debug!(error = %e, "Could not send message to the sync service"));
    }

    /// Send a message to `network_tx`.
    ///
    /// Creates a log if there is an internal error.
    fn send_network_message(&self, message: NetworkMessage<T::EthSpec>) {
        self.network_tx.send(message).unwrap_or_else(|e| {
            debug!(error = %e, "Could not send message to the network service. Likely shutdown")
        });
    }

    pub async fn fetch_engine_blobs_and_publish(
        self: &Arc<Self>,
        header: Arc<PartialDataColumnHeader<T::EthSpec>>,
        block_root: Hash256,
        publish_blobs: bool,
    ) {
        if self.chain.config.disable_get_blobs {
            return;
        }
        let epoch = header.slot().epoch(T::EthSpec::slots_per_epoch());
        let custody_columns = self.chain.sampling_columns_for_epoch(epoch);
        let self_cloned = self.clone();
        let publish_fn = move |columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>| {
            if publish_blobs {
                self_cloned.publish_data_columns_gradually(
                    columns.into_iter().map(|c| c.clone_arc()).collect(),
                    block_root,
                );
            }
        };

        match fetch_and_process_engine_blobs(
            self.chain.clone(),
            block_root,
            header.clone(),
            custody_columns,
            publish_fn,
        )
        .await
        {
            Ok(Some(availability)) => match availability {
                AvailabilityProcessingStatus::Imported(_) => {
                    debug!(
                        result = "imported block and custody columns",
                        %block_root,
                        "Block components retrieved from EL"
                    );
                    self.chain.recompute_head_at_current_slot().await;
                }
                AvailabilityProcessingStatus::MissingComponents(_, _) => {
                    debug!(
                        %block_root,
                        "Still missing blobs after engine blobs processed successfully"
                    );
                }
            },
            Ok(None) => {
                debug!(
                    %block_root,
                    "Fetch blobs completed without import"
                );
            }
            Err(FetchEngineBlobError::BlobProcessingError(BlockError::DuplicateFullyImported(
                ..,
            ))) => {
                debug!(
                    %block_root,
                    "Fetch blobs duplicate import"
                );
            }
            Err(e) => {
                error!(
                    error = ?e,
                    %block_root,
                    "Error fetching or processing blobs from EL"
                );
            }
        }

        // Publish partial columns without eager send
        // TODO(gloas): implement publish partial columns without eager send
        if let Some(assembler) = self.chain.data_availability_checker.partial_assembler() {
            let columns = assembler.get_partials_and_mark_as_local_fetched(block_root, &header);
            if !columns.is_empty() {
                debug!(block = %block_root, "Publishing all partials after getBlobs");
                self.send_network_message(NetworkMessage::PublishPartialColumns {
                    columns: columns
                        .into_iter()
                        .map(|partial| partial.into_inner())
                        .collect(),
                    header,
                });
            } else {
                debug!(block = %block_root, "No partials to publish after getBlobs");
            }
        }
    }

    /// Attempts to reconstruct all data columns if the conditions checked in
    /// [`DataAvailabilityCheckerInner::check_and_set_reconstruction_started`] are satisfied.
    #[instrument(level = "debug", skip_all, fields(?block_root))]
    async fn attempt_data_column_reconstruction(self: &Arc<Self>, slot: Slot, block_root: Hash256) {
        let result = self.chain.reconstruct_data_columns(slot, block_root).await;

        match result {
            Ok(Some((availability_processing_status, data_columns_to_publish))) => {
                self.publish_data_columns_gradually(data_columns_to_publish, block_root);
                match &availability_processing_status {
                    AvailabilityProcessingStatus::Imported(hash) => {
                        debug!(
                            result = "imported block and custody columns",
                            block_hash = %hash,
                            "Block components available via reconstruction"
                        );
                        self.chain.recompute_head_at_current_slot().await;
                    }
                    AvailabilityProcessingStatus::MissingComponents(_, _) => {
                        debug!(
                            result = "imported all custody columns",
                            %block_root,
                            "Block components still missing block after reconstruction"
                        );
                    }
                }
            }
            Ok(None) => {
                // reason is tracked via the `KZG_DATA_COLUMN_RECONSTRUCTION_INCOMPLETE_TOTAL` metric
                trace!(
                    %block_root,
                    "Reconstruction not required for block"
                );
            }
            Err(BlockError::DuplicateFullyImported(_)) => {
                debug!("Block already imported in parallel with reconstruction");
            }
            Err(e) => {
                error!(
                    %block_root,
                    error = ?e,
                    "Error during data column reconstruction"
                );
            }
        }
    }

    /// This function gradually publishes data columns to the network in randomised batches.
    ///
    /// This is an optimisation to reduce outbound bandwidth and ensures each column is published
    /// by some nodes on the network as soon as possible. Our hope is that some columns arrive from
    /// other nodes in the meantime, obviating the need for us to publish them. If no other
    /// publisher exists for a column, it will eventually get published here.
    #[instrument(level="debug", skip_all, fields(?block_root, data_column_count=data_columns_to_publish.len()))]
    fn publish_data_columns_gradually(
        self: &Arc<Self>,
        mut data_columns_to_publish: DataColumnSidecarList<T::EthSpec>,
        block_root: Hash256,
    ) {
        let self_clone = self.clone();

        self.executor.spawn(
            async move {
                let chain = self_clone.chain.clone();
                let publish_fn = |columns: DataColumnSidecarList<T::EthSpec>| {
                    self_clone.send_network_message(NetworkMessage::Publish {
                        messages: columns
                            .into_iter()
                            .map(|d| {
                                let subnet =
                                    DataColumnSubnetId::from_column_index(*d.index(), &chain.spec);
                                PubsubMessage::DataColumnSidecar(Box::new((subnet, d)))
                            })
                            .collect(),
                    });
                };

                // Permute the columns and split them into batches.
                // The hope is that we won't need to publish some columns because we will receive them
                // on gossip from other nodes.
                data_columns_to_publish.shuffle(&mut rand::rng());

                let blob_publication_batch_interval = chain.config.blob_publication_batch_interval;
                let blob_publication_batches = chain.config.blob_publication_batches;
                let number_of_columns = T::EthSpec::number_of_columns();
                let batch_size = number_of_columns / blob_publication_batches;
                let mut publish_count = 0usize;

                for batch in data_columns_to_publish.chunks(batch_size) {
                    let publishable = batch
                        .iter()
                        .filter_map(|col| match observe_gossip_data_column(col, &chain) {
                            Ok(()) => Some(col.clone()),
                            Err(GossipDataColumnError::PriorKnown { .. }) => None,
                            Err(e) => {
                                warn!(
                                    error = ?e,
                                    "Previously verified data column is invalid"
                                );
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    if !publishable.is_empty() {
                        debug!(
                            publish_count = publishable.len(),
                            ?block_root,
                            "Publishing data column batch"
                        );
                        publish_count += publishable.len();
                        publish_fn(publishable);
                    }

                    tokio::time::sleep(blob_publication_batch_interval).await;
                }

                debug!(
                    batch_size,
                    batch_interval = blob_publication_batch_interval.as_millis(),
                    data_columns_to_publish_count = data_columns_to_publish.len(),
                    publish_count,
                    ?block_root,
                    "Batch data column publishing complete"
                )
            },
            "gradual_data_column_publication",
        );
    }
}

pub(crate) type TestBeaconChainType<E> = Witness<ManualSlotClock, E, MemoryStore, MemoryStore>;

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
    ) -> (Self, mpsc::Receiver<BeaconWorkEvent<E>>) {
        let BeaconProcessorChannels {
            beacon_processor_tx,
            beacon_processor_rx,
        } = <_>::default();

        let (network_tx, _network_rx) = mpsc::unbounded_channel();

        let network_beacon_processor = Self {
            beacon_processor_send: beacon_processor_tx,
            duplicate_cache: DuplicateCache::default(),
            chain,
            network_tx,
            sync_tx,
            network_globals,
            invalid_block_storage: InvalidBlockStorage::Disabled,
            executor,
        };

        (network_beacon_processor, beacon_processor_rx)
    }

    /// Constructs a mostly non-functional `NetworkBeaconProcessor` from a test harness,
    /// suitable for directly calling gossip processing methods in tests.
    pub fn null_from_harness(harness: &BeaconChainHarness<EphemeralHarnessType<E>>) -> Self {
        let network_globals = NetworkGlobals::new_test_globals(
            vec![],
            Arc::new(NetworkConfig::default()),
            harness.spec.clone(),
        );

        Self::null_for_testing(
            Arc::new(network_globals),
            mpsc::unbounded_channel().0,
            harness.chain.clone(),
            harness.runtime.task_executor.clone(),
        )
        .0
    }
}
