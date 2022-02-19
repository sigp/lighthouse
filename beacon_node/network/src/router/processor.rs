use crate::beacon_processor::{
    BeaconProcessor, WorkEvent as BeaconWorkEvent, MAX_WORK_EVENT_QUEUE_LEN,
};
use crate::service::{NetworkMessage, RequestId};
use crate::status::status_message;
use crate::sync::manager::RequestId as SyncId;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::rpc::*;
use lighthouse_network::{
    Client, MessageId, NetworkGlobals, PeerId, PeerRequestId, Request, Response,
};
use slog::{debug, error, o, trace, warn};
use std::cmp;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::SyncCommitteeMessage;
use tokio::sync::mpsc;
use lighthouse_network::rpc::methods::TxBlobsByRangeRequest;
use types::{Attestation, AttesterSlashing, BlobWrapper, EthSpec, ProposerSlashing, SignedAggregateAndProof, SignedBeaconBlock, SignedContributionAndProof, SignedVoluntaryExit, SubnetId, SyncSubnetId};

/// Processes validated messages from the network. It relays necessary data to the syncing thread
/// and processes blocks from the pubsub network.
pub struct Processor<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A channel to the syncing thread.
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    /// A network context to return and handle RPC requests.
    network: HandlerNetworkContext<T::EthSpec>,
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,
    /// The `RPCHandler` logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> Processor<T> {
    /// Instantiate a `Processor` instance
    pub fn new(
        executor: task_executor::TaskExecutor,
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        log: &slog::Logger,
    ) -> Self {
        let sync_logger = log.new(o!("service"=> "sync"));
        let (beacon_processor_send, beacon_processor_receive) =
            mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN);

        // spawn the sync thread
        let sync_send = crate::sync::manager::spawn(
            executor.clone(),
            beacon_chain.clone(),
            network_globals.clone(),
            network_send.clone(),
            beacon_processor_send.clone(),
            sync_logger,
        );

        BeaconProcessor {
            beacon_chain: Arc::downgrade(&beacon_chain),
            network_tx: network_send.clone(),
            sync_tx: sync_send.clone(),
            network_globals,
            executor,
            max_workers: cmp::max(1, num_cpus::get()),
            current_workers: 0,
            importing_blocks: Default::default(),
            log: log.clone(),
        }
        .spawn_manager(beacon_processor_receive, None);

        Processor {
            chain: beacon_chain,
            sync_send,
            network: HandlerNetworkContext::new(network_send, log.clone()),
            beacon_processor_send,
            log: log.new(o!("service" => "router")),
        }
    }

    fn send_to_sync(&mut self, message: SyncMessage<T::EthSpec>) {
        self.sync_send.send(message).unwrap_or_else(|e| {
            warn!(
                self.log,
                "Could not send message to the sync service";
                "error" => %e,
            )
        });
    }

    /// Handle a peer disconnect.
    ///
    /// Removes the peer from the manager.
    pub fn on_disconnect(&mut self, peer_id: PeerId) {
        self.send_to_sync(SyncMessage::Disconnect(peer_id));
    }

    /// An error occurred during an RPC request. The state is maintained by the sync manager, so
    /// this function notifies the sync manager of the error.
    pub fn on_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId) {
        // Check if the failed RPC belongs to sync
        if let RequestId::Sync(request_id) = request_id {
            self.send_to_sync(SyncMessage::RpcError {
                peer_id,
                request_id,
            });
        }
    }

    /// Sends a `Status` message to the peer.
    ///
    /// Called when we first connect to a peer, or when the PeerManager determines we need to
    /// re-status.
    pub fn send_status(&mut self, peer_id: PeerId) {
        let status_message = status_message(&self.chain);
        debug!(self.log, "Sending Status Request"; "peer" => %peer_id, &status_message);
        self.network
            .send_processor_request(peer_id, Request::Status(status_message));
    }

    /// Handle a `Status` request.
    ///
    /// Processes the `Status` from the remote peer and sends back our `Status`.
    pub fn on_status_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        status: StatusMessage,
    ) {
        debug!(self.log, "Received Status Request"; "peer_id" => %peer_id, &status);

        // Say status back.
        self.network.send_response(
            peer_id,
            Response::Status(status_message(&self.chain)),
            request_id,
        );

        self.send_beacon_processor_work(BeaconWorkEvent::status_message(peer_id, status))
    }

    /// Process a `Status` response from a peer.
    pub fn on_status_response(&mut self, peer_id: PeerId, status: StatusMessage) {
        debug!(self.log, "Received Status Response"; "peer_id" => %peer_id, &status);
        self.send_beacon_processor_work(BeaconWorkEvent::status_message(peer_id, status))
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub fn on_blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::blocks_by_roots_request(
            peer_id, request_id, request,
        ))
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub fn on_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlocksByRangeRequest,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::blocks_by_range_request(
            peer_id, request_id, req,
        ))
    }

    /// Handle a `BlocksByRange` response from the peer.
    /// A `beacon_block` behaves as a stream which is terminated on a `None` response.
    pub fn on_blocks_by_range_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) {
        let request_id = match request_id {
            RequestId::Sync(sync_id) => match sync_id {
                SyncId::SingleBlock { .. } | SyncId::ParentLookup { .. } => {
                    unreachable!("Block lookups do not request BBRange requests")
                }
                id @ (SyncId::BackFillSync { .. } | SyncId::RangeSync { .. }) => id,
            },
            RequestId::Router => unreachable!("All BBRange requests belong to sync"),
        };

        trace!(
            self.log,
            "Received BlocksByRange Response";
            "peer" => %peer_id,
        );

        self.send_to_sync(SyncMessage::RpcBlock {
            peer_id,
            request_id,
            beacon_block,
            seen_timestamp: timestamp_now(),
        });
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub fn on_tx_blobs_by_range_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: TxBlobsByRangeRequest,
    ) {
        //FIXME(sean)
    }

    pub fn on_tx_blobs_by_range_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        blob_wrapper: Option<Box<BlobWrapper<T::EthSpec>>>,
    ) {
        //FIXME(sean)
    }

    /// Handle a `BlocksByRoot` response from the peer.
    pub fn on_blocks_by_root_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) {
        let request_id = match request_id {
            RequestId::Sync(sync_id) => match sync_id {
                id @ (SyncId::SingleBlock { .. } | SyncId::ParentLookup { .. }) => id,
                SyncId::BackFillSync { .. } | SyncId::RangeSync { .. } => {
                    unreachable!("Batch syncing do not request BBRoot requests")
                }
            },
            RequestId::Router => unreachable!("All BBRoot requests belong to sync"),
        };

        trace!(
            self.log,
            "Received BlocksByRoot Response";
            "peer" => %peer_id,
        );
        self.send_to_sync(SyncMessage::RpcBlock {
            peer_id,
            request_id,
            beacon_block,
            seen_timestamp: timestamp_now(),
        });
    }

    /// Process a gossip message declaring a new block.
    ///
    /// Attempts to apply to block to the beacon chain. May queue the block for later processing.
    ///
    /// Returns a `bool` which, if `true`, indicates we should forward the block to our peers.
    pub fn on_block_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_beacon_block(
            message_id,
            peer_id,
            peer_client,
            block,
            timestamp_now(),
        ))
    }

    pub fn on_unaggregated_attestation_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        unaggregated_attestation: Attestation<T::EthSpec>,
        subnet_id: SubnetId,
        should_process: bool,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::unaggregated_attestation(
            message_id,
            peer_id,
            unaggregated_attestation,
            subnet_id,
            should_process,
            timestamp_now(),
        ))
    }

    pub fn on_aggregated_attestation_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::aggregated_attestation(
            message_id,
            peer_id,
            aggregate,
            timestamp_now(),
        ))
    }

    pub fn on_voluntary_exit_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_voluntary_exit(
            message_id,
            peer_id,
            voluntary_exit,
        ))
    }

    pub fn on_proposer_slashing_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_proposer_slashing(
            message_id,
            peer_id,
            proposer_slashing,
        ))
    }

    pub fn on_attester_slashing_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<T::EthSpec>>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_attester_slashing(
            message_id,
            peer_id,
            attester_slashing,
        ))
    }

    pub fn on_sync_committee_signature_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        sync_signature: SyncCommitteeMessage,
        subnet_id: SyncSubnetId,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_sync_signature(
            message_id,
            peer_id,
            sync_signature,
            subnet_id,
            timestamp_now(),
        ))
    }

    pub fn on_sync_committee_contribution_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        sync_contribution: SignedContributionAndProof<T::EthSpec>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_sync_contribution(
            message_id,
            peer_id,
            sync_contribution,
            timestamp_now(),
        ))
    }

    fn send_beacon_processor_work(&mut self, work: BeaconWorkEvent<T>) {
        self.beacon_processor_send
            .try_send(work)
            .unwrap_or_else(|e| {
                let work_type = match &e {
                    mpsc::error::TrySendError::Closed(work)
                    | mpsc::error::TrySendError::Full(work) => work.work_type(),
                };
                error!(&self.log, "Unable to send message to the beacon processor";
                    "error" => %e, "type" => work_type)
            })
    }
}

/// Wraps a Network Channel to employ various RPC related network functionality for the
/// processor.
#[derive(Clone)]
pub struct HandlerNetworkContext<T: EthSpec> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T>>,
    /// Logger for the `NetworkContext`.
    log: slog::Logger,
}

impl<T: EthSpec> HandlerNetworkContext<T> {
    pub fn new(network_send: mpsc::UnboundedSender<NetworkMessage<T>>, log: slog::Logger) -> Self {
        Self { network_send, log }
    }

    /// Sends a message to the network task.
    fn inform_network(&mut self, msg: NetworkMessage<T>) {
        self.network_send.send(msg).unwrap_or_else(
            |e| warn!(self.log, "Could not send message to the network service"; "error" => %e),
        )
    }

    /// Sends a request to the network task.
    pub fn send_processor_request(&mut self, peer_id: PeerId, request: Request) {
        self.inform_network(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Router,
            request,
        })
    }

    /// Sends a response to the network task.
    pub fn send_response(&mut self, peer_id: PeerId, response: Response<T>, id: PeerRequestId) {
        self.inform_network(NetworkMessage::SendResponse {
            peer_id,
            id,
            response,
        })
    }
}

fn timestamp_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
}
