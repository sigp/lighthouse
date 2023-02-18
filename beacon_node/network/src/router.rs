//! This module handles incoming network messages.
//!
//! It routes the messages to appropriate services.
//! It handles requests at the application layer in its associated processor and directs
//! syncing-related responses to the Sync manager.
#![allow(clippy::unit_arg)]

use crate::error;
use crate::service::{NetworkMessage, RequestId};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::prelude::*;
use lighthouse_network::{
    MessageId, NetworkGlobals, PeerId, PeerRequestId, PubsubMessage, Request, Response,
};
use slog::{debug, o, trace};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use types::EthSpec;
// imports from processor
use crate::beacon_processor::{
    BeaconProcessor, WorkEvent as BeaconWorkEvent, MAX_WORK_EVENT_QUEUE_LEN,
};
use crate::status::status_message;
use crate::sync::manager::RequestId as SyncId;
use crate::sync::SyncMessage;
use lighthouse_network::rpc::*;
use lighthouse_network::Client;
use slog::{error, warn};
use std::cmp;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::SyncCommitteeMessage;
use types::{
    Attestation, AttesterSlashing, LightClientFinalityUpdate, LightClientOptimisticUpdate,
    ProposerSlashing, SignedAggregateAndProof, SignedBeaconBlock, SignedContributionAndProof,
    SignedVoluntaryExit, SubnetId, SyncSubnetId,
};

/// Handles messages received from the network and client and organises syncing. This
/// functionality of this struct is to validate an decode messages from the network before
/// passing them to the internal message processor. The message processor spawns a syncing thread
/// which manages which blocks need to be requested and processed.
pub struct Router<T: BeaconChainTypes> {
    /// Access to the peer db.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    // -----This was the processor before-----
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A channel to the syncing thread.
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    /// A network context to return and handle RPC requests.
    network: HandlerNetworkContext<T::EthSpec>,
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,
    /// The `RPCHandler` logger.
    processor_log: slog::Logger,
    // --------------------------------------
    /// The `Router` logger.
    log: slog::Logger,
}

/// Types of messages the handler can receive.
#[derive(Debug)]
pub enum RouterMessage<T: EthSpec> {
    /// We have initiated a connection to a new peer.
    PeerDialed(PeerId),
    /// Peer has disconnected,
    PeerDisconnected(PeerId),
    /// An RPC request has been received.
    RPCRequestReceived {
        peer_id: PeerId,
        id: PeerRequestId,
        request: Request,
    },
    /// An RPC response has been received.
    RPCResponseReceived {
        peer_id: PeerId,
        request_id: RequestId,
        response: Response<T>,
    },
    /// An RPC request failed
    RPCFailed {
        peer_id: PeerId,
        request_id: RequestId,
    },
    /// A gossip message has been received. The fields are: message id, the peer that sent us this
    /// message, the message itself and a bool which indicates if the message should be processed
    /// by the beacon chain after successful verification.
    PubsubMessage(MessageId, PeerId, PubsubMessage<T>, bool),
    /// The peer manager has requested we re-status a peer.
    StatusPeer(PeerId),
}

impl<T: BeaconChainTypes> Router<T> {
    /// Initializes and runs the Router.
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        executor: task_executor::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<RouterMessage<T::EthSpec>>> {
        let message_handler_log = log.new(o!("service"=> "router"));
        trace!(message_handler_log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();

        // -----This was Processor::new-----
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
            network_globals: network_globals.clone(),
            executor: executor.clone(),
            max_workers: cmp::max(1, num_cpus::get()),
            current_workers: 0,
            importing_blocks: Default::default(),
            log: log.clone(),
        }
        .spawn_manager(beacon_processor_receive, None);
        //----------

        // generate the Message handler
        let mut handler = Router {
            network_globals,
            chain: beacon_chain,
            sync_send,
            network: HandlerNetworkContext::new(network_send, log.clone()),
            beacon_processor_send,
            processor_log: log.new(o!("service" => "router")),
            log: message_handler_log,
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(
            async move {
                debug!(log, "Network message router started");
                UnboundedReceiverStream::new(handler_recv)
                    .for_each(move |msg| future::ready(handler.handle_message(msg)))
                    .await;
            },
            "router",
        );

        Ok(handler_send)
    }

    /// Handle all messages incoming from the network service.
    fn handle_message(&mut self, message: RouterMessage<T::EthSpec>) {
        match message {
            // we have initiated a connection to a peer or the peer manager has requested a
            // re-status
            RouterMessage::PeerDialed(peer_id) | RouterMessage::StatusPeer(peer_id) => {
                self.send_status(peer_id);
            }
            // A peer has disconnected
            RouterMessage::PeerDisconnected(peer_id) => {
                self.on_disconnect(peer_id);
            }
            RouterMessage::RPCRequestReceived {
                peer_id,
                id,
                request,
            } => {
                self.handle_rpc_request(peer_id, id, request);
            }
            RouterMessage::RPCResponseReceived {
                peer_id,
                request_id,
                response,
            } => {
                self.handle_rpc_response(peer_id, request_id, response);
            }
            RouterMessage::RPCFailed {
                peer_id,
                request_id,
            } => {
                self.on_rpc_error(peer_id, request_id);
            }
            RouterMessage::PubsubMessage(id, peer_id, gossip, should_process) => {
                self.handle_gossip(id, peer_id, gossip, should_process);
            }
        }
    }

    /* RPC - Related functionality */

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, id: PeerRequestId, request: Request) {
        if !self.network_globals.peers.read().is_connected(&peer_id) {
            debug!(self.log, "Dropping request of disconnected peer"; "peer_id" => %peer_id, "request" => ?request);
            return;
        }
        match request {
            Request::Status(status_message) => self.on_status_request(peer_id, id, status_message),
            Request::BlocksByRange(request) => {
                self.on_blocks_by_range_request(peer_id, id, request)
            }
            Request::BlocksByRoot(request) => self.on_blocks_by_root_request(peer_id, id, request),
            Request::LightClientBootstrap(request) => {
                self.on_lightclient_bootstrap(peer_id, id, request)
            }
        }
    }

    /// An RPC response has been received from the network.
    // we match on id and ignore responses past the timeout.
    fn handle_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        response: Response<T::EthSpec>,
    ) {
        // an error could have occurred.
        match response {
            Response::Status(status_message) => {
                self.on_status_response(peer_id, status_message);
            }
            Response::BlocksByRange(beacon_block) => {
                self.on_blocks_by_range_response(peer_id, request_id, beacon_block);
            }
            Response::BlocksByRoot(beacon_block) => {
                self.on_blocks_by_root_response(peer_id, request_id, beacon_block);
            }
            Response::LightClientBootstrap(_) => unreachable!(),
        }
    }

    /// Handle RPC messages.
    /// Note: `should_process` is currently only useful for the `Attestation` variant.
    /// if `should_process` is `false`, we only propagate the message on successful verification,
    /// else, we propagate **and** import into the beacon chain.
    fn handle_gossip(
        &mut self,
        id: MessageId,
        peer_id: PeerId,
        gossip_message: PubsubMessage<T::EthSpec>,
        should_process: bool,
    ) {
        match gossip_message {
            // Attestations should never reach the router.
            PubsubMessage::AggregateAndProofAttestation(aggregate_and_proof) => {
                self.on_aggregated_attestation_gossip(id, peer_id, *aggregate_and_proof);
            }
            PubsubMessage::Attestation(subnet_attestation) => {
                self.on_unaggregated_attestation_gossip(
                    id,
                    peer_id,
                    subnet_attestation.1.clone(),
                    subnet_attestation.0,
                    should_process,
                );
            }
            PubsubMessage::BeaconBlock(block) => {
                self.on_block_gossip(id, peer_id, self.network_globals.client(&peer_id), block);
            }
            PubsubMessage::VoluntaryExit(exit) => {
                debug!(self.log, "Received a voluntary exit"; "peer_id" => %peer_id);
                self.on_voluntary_exit_gossip(id, peer_id, exit);
            }
            PubsubMessage::ProposerSlashing(proposer_slashing) => {
                debug!(
                    self.log,
                    "Received a proposer slashing";
                    "peer_id" => %peer_id
                );
                self.on_proposer_slashing_gossip(id, peer_id, proposer_slashing);
            }
            PubsubMessage::AttesterSlashing(attester_slashing) => {
                debug!(
                    self.log,
                    "Received a attester slashing";
                    "peer_id" => %peer_id
                );
                self.on_attester_slashing_gossip(id, peer_id, attester_slashing);
            }
            PubsubMessage::SignedContributionAndProof(contribution_and_proof) => {
                trace!(
                    self.log,
                    "Received sync committee aggregate";
                    "peer_id" => %peer_id
                );
                self.on_sync_committee_contribution_gossip(id, peer_id, *contribution_and_proof);
            }
            PubsubMessage::SyncCommitteeMessage(sync_committtee_msg) => {
                trace!(
                    self.log,
                    "Received sync committee signature";
                    "peer_id" => %peer_id
                );
                self.on_sync_committee_signature_gossip(
                    id,
                    peer_id,
                    sync_committtee_msg.1,
                    sync_committtee_msg.0,
                );
            }
            PubsubMessage::LightClientFinalityUpdate(light_client_finality_update) => {
                trace!(
                    self.log,
                    "Received light client finality update";
                    "peer_id" => %peer_id
                );
                self.on_light_client_finality_update_gossip(
                    id,
                    peer_id,
                    light_client_finality_update,
                );
            }
            PubsubMessage::LightClientOptimisticUpdate(light_client_optimistic_update) => {
                trace!(
                    self.log,
                    "Received light client optimistic update";
                    "peer_id" => %peer_id
                );
                self.on_light_client_optimistic_update_gossip(
                    id,
                    peer_id,
                    light_client_optimistic_update,
                );
            }
        }
    }

    //-----These were the processor methods-----

    fn send_to_sync(&mut self, message: SyncMessage<T::EthSpec>) {
        self.sync_send.send(message).unwrap_or_else(|e| {
            warn!(
                self.processor_log,
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
        debug!(self.processor_log, "Sending Status Request"; "peer" => %peer_id, &status_message);
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
        debug!(self.processor_log, "Received Status Request"; "peer_id" => %peer_id, &status);

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
        debug!(self.processor_log, "Received Status Response"; "peer_id" => %peer_id, &status);
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

    /// Handle a `LightClientBootstrap` request from the peer.
    pub fn on_lightclient_bootstrap(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: LightClientBootstrapRequest,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::lightclient_bootstrap_request(
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
            self.processor_log,
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
            self.processor_log,
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

    pub fn on_light_client_finality_update_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        light_client_finality_update: Box<LightClientFinalityUpdate<T::EthSpec>>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_light_client_finality_update(
            message_id,
            peer_id,
            light_client_finality_update,
            timestamp_now(),
        ))
    }

    pub fn on_light_client_optimistic_update_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        light_client_optimistic_update: Box<LightClientOptimisticUpdate<T::EthSpec>>,
    ) {
        self.send_beacon_processor_work(BeaconWorkEvent::gossip_light_client_optimistic_update(
            message_id,
            peer_id,
            light_client_optimistic_update,
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
                error!(&self.processor_log, "Unable to send message to the beacon processor";
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
