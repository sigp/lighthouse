use crate::{
    service::NetworkMessage,
    sync::{manager::BlockProcessType, SyncMessage},
};
use beacon_chain::{
    builder::Witness, eth1_chain::CachingEth1Backend, test_utils::BeaconChainHarness, BeaconChain,
};
use beacon_chain::{BeaconChainTypes, NotifyExecutionLayer};
use beacon_processor::{
    work_reprocessing_queue::ReprocessQueueMessage, BeaconProcessorSend, DuplicateCache,
    GossipAggregatePackage, GossipAttestationPackage, Work, WorkEvent as BeaconWorkEvent,
    MAX_SCHEDULED_WORK_QUEUE_LEN, MAX_WORK_EVENT_QUEUE_LEN,
};
use environment::null_logger;
use lighthouse_network::{
    rpc::{BlocksByRangeRequest, BlocksByRootRequest, LightClientBootstrapRequest, StatusMessage},
    Client, MessageId, NetworkGlobals, PeerId, PeerRequestId,
};
use slog::{debug, Logger};
use slot_clock::ManualSlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::MemoryStore;
use task_executor::test_utils::TestRuntime;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, error::TrySendError};
use types::*;

pub use sync_methods::ChainSegmentProcessId;

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
                attestation: GossipAttestationPackage {
                    message_id,
                    peer_id,
                    attestation: Box::new(attestation),
                    subnet_id,
                    should_import,
                    seen_timestamp,
                },
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

        let beacon_block_root = aggregate.message.aggregate.data.beacon_block_root;
        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::GossipAggregate {
                aggregate: GossipAggregatePackage {
                    message_id,
                    peer_id,
                    aggregate: Box::new(aggregate),
                    beacon_block_root,
                    seen_timestamp,
                },
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
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
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

    /// Create a new work event to import `blocks` as a beacon chain segment.
    pub fn send_chain_segment(
        self: &Arc<Self>,
        process_id: ChainSegmentProcessId,
        blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
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
        request_id: PeerRequestId,
        request: BlocksByRangeRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move |send_idle_on_drop| {
            let executor = processor.executor.clone();
            processor.handle_blocks_by_range_request(
                executor,
                send_idle_on_drop,
                peer_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRangeRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `BlocksByRootRequest`s from the RPC network.
    pub fn send_blocks_by_roots_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn = move |send_idle_on_drop| {
            let executor = processor.executor.clone();
            processor.handle_blocks_by_root_request(
                executor,
                send_idle_on_drop,
                peer_id,
                request_id,
                request,
            )
        };

        self.try_send(BeaconWorkEvent {
            drop_during_sync: false,
            work: Work::BlocksByRootsRequest(Box::new(process_fn)),
        })
    }

    /// Create a new work event to process `LightClientBootstrap`s from the RPC network.
    pub fn send_lightclient_bootstrap_request(
        self: &Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: LightClientBootstrapRequest,
    ) -> Result<(), Error<T::EthSpec>> {
        let processor = self.clone();
        let process_fn =
            move || processor.handle_light_client_bootstrap(peer_id, request_id, request);

        self.try_send(BeaconWorkEvent {
            drop_during_sync: true,
            work: Work::LightClientBootstrapRequest(Box::new(process_fn)),
        })
    }

    /// Send a message to `sync_tx`.
    ///
    /// Creates a log if there is an internal error.
    fn send_sync_message(&self, message: SyncMessage<T::EthSpec>) {
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
    ) -> (Self, mpsc::Receiver<BeaconWorkEvent<E>>) {
        let (beacon_processor_send, beacon_processor_receive) =
            mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN);
        let (network_tx, _network_rx) = mpsc::unbounded_channel();
        let (sync_tx, _sync_rx) = mpsc::unbounded_channel();
        let (reprocess_tx, _reprocess_rx) = mpsc::channel(MAX_SCHEDULED_WORK_QUEUE_LEN);
        let log = null_logger().unwrap();
        let harness: BeaconChainHarness<TestBeaconChainType<E>> =
            BeaconChainHarness::builder(E::default())
                .spec(E::default_spec())
                .deterministic_keypairs(8)
                .logger(log.clone())
                .fresh_ephemeral_store()
                .mock_execution_layer()
                .build();
        let runtime = TestRuntime::default();

        let network_beacon_processor = Self {
            beacon_processor_send: BeaconProcessorSend(beacon_processor_send),
            duplicate_cache: DuplicateCache::default(),
            chain: harness.chain,
            network_tx,
            sync_tx,
            reprocess_tx,
            network_globals,
            invalid_block_storage: InvalidBlockStorage::Disabled,
            executor: runtime.task_executor.clone(),
            log,
        };

        (network_beacon_processor, beacon_processor_receive)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn queued_block_delay_is_sane() {
        assert!(
            beacon_processor::work_reprocessing_queue::ADDITIONAL_QUEUED_BLOCK_DELAY
                < beacon_chain::MAXIMUM_GOSSIP_CLOCK_DISPARITY
        );
    }
}
