//! This module handles incoming network messages.
//!
//! It routes the messages to appropriate services.
//! It handles requests at the application layer in its associated processor and directs
//! syncing-related responses to the Sync manager.
#![allow(clippy::unit_arg)]

use crate::error;
use crate::network_beacon_processor::{InvalidBlockStorage, NetworkBeaconProcessor};
use crate::service::{NetworkMessage, RequestId};
use crate::status::status_message;
use crate::sync::manager::RequestId as SyncId;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use beacon_processor::{
    work_reprocessing_queue::ReprocessQueueMessage, BeaconProcessorSend, DuplicateCache,
};
use futures::prelude::*;
use lighthouse_network::rpc::*;
use lighthouse_network::{
    MessageId, NetworkGlobals, PeerId, PeerRequestId, PubsubMessage, Request, Response,
};
use logging::TimeLatch;
use slog::{crit, debug, o, trace};
use slog::{error, warn};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use types::{BlobSidecar, DataColumnSidecar, EthSpec, SignedBeaconBlock};

/// Handles messages from the network and routes them to the appropriate service to be handled.
pub struct Router<T: BeaconChainTypes> {
    /// Access to the peer db and network information.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A channel to the syncing thread.
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    /// A network context to return and handle RPC requests.
    network: HandlerNetworkContext<T::EthSpec>,
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
    /// The `Router` logger.
    log: slog::Logger,
    /// Provides de-bounce functionality for logging.
    logger_debounce: TimeLatch,
}

/// Types of messages the router can receive.
#[derive(Debug)]
pub enum RouterMessage<T: EthSpec> {
    /// Peer has disconnected.
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
        error: RPCError,
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
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        executor: task_executor::TaskExecutor,
        invalid_block_storage: InvalidBlockStorage,
        beacon_processor_send: BeaconProcessorSend<T::EthSpec>,
        beacon_processor_reprocess_tx: mpsc::Sender<ReprocessQueueMessage>,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<RouterMessage<T::EthSpec>>> {
        let message_handler_log = log.new(o!("service"=> "router"));
        trace!(message_handler_log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();

        let sync_logger = log.new(o!("service"=> "sync"));
        // generate the message channel
        let (sync_send, sync_recv) = mpsc::unbounded_channel::<SyncMessage<T::EthSpec>>();

        let network_beacon_processor = NetworkBeaconProcessor {
            beacon_processor_send,
            duplicate_cache: DuplicateCache::default(),
            chain: beacon_chain.clone(),
            network_tx: network_send.clone(),
            sync_tx: sync_send.clone(),
            reprocess_tx: beacon_processor_reprocess_tx,
            network_globals: network_globals.clone(),
            invalid_block_storage,
            executor: executor.clone(),
            log: log.clone(),
        };
        let network_beacon_processor = Arc::new(network_beacon_processor);

        // spawn the sync thread
        crate::sync::manager::spawn(
            executor.clone(),
            beacon_chain.clone(),
            network_send.clone(),
            network_beacon_processor.clone(),
            sync_recv,
            sync_logger,
        );

        // generate the Message handler
        let mut handler = Router {
            network_globals,
            chain: beacon_chain,
            sync_send,
            network: HandlerNetworkContext::new(network_send, log.clone()),
            network_beacon_processor,
            log: message_handler_log,
            logger_debounce: TimeLatch::default(),
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
            RouterMessage::StatusPeer(peer_id) => {
                self.send_status(peer_id);
            }
            // A peer has disconnected
            RouterMessage::PeerDisconnected(peer_id) => {
                self.send_to_sync(SyncMessage::Disconnect(peer_id));
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
                error,
            } => {
                self.on_rpc_error(peer_id, request_id, error);
            }
            RouterMessage::PubsubMessage(id, peer_id, gossip, should_process) => {
                self.handle_gossip(id, peer_id, gossip, should_process);
            }
        }
    }

    /* RPC - Related functionality */

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, request_id: PeerRequestId, request: Request) {
        if !self.network_globals.peers.read().is_connected(&peer_id) {
            debug!(self.log, "Dropping request of disconnected peer"; "peer_id" => %peer_id, "request" => ?request);
            return;
        }
        match request {
            Request::Status(status_message) => {
                self.on_status_request(peer_id, request_id, status_message)
            }
            Request::BlocksByRange(request) => self.handle_beacon_processor_send_result(
                self.network_beacon_processor
                    .send_blocks_by_range_request(peer_id, request_id, request),
            ),
            Request::BlocksByRoot(request) => self.handle_beacon_processor_send_result(
                self.network_beacon_processor
                    .send_blocks_by_roots_request(peer_id, request_id, request),
            ),
            Request::BlobsByRange(request) => self.handle_beacon_processor_send_result(
                self.network_beacon_processor
                    .send_blobs_by_range_request(peer_id, request_id, request),
            ),
            Request::BlobsByRoot(request) => self.handle_beacon_processor_send_result(
                self.network_beacon_processor
                    .send_blobs_by_roots_request(peer_id, request_id, request),
            ),
            Request::DataColumnsByRoot(request) => self.handle_beacon_processor_send_result(
                self.network_beacon_processor
                    .send_data_columns_by_roots_request(peer_id, request_id, request),
            ),
            Request::LightClientBootstrap(request) => self.handle_beacon_processor_send_result(
                self.network_beacon_processor
                    .send_light_client_bootstrap_request(peer_id, request_id, request),
            ),
        }
    }

    /// An RPC response has been received from the network.
    fn handle_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        response: Response<T::EthSpec>,
    ) {
        match response {
            Response::Status(status_message) => {
                debug!(self.log, "Received Status Response"; "peer_id" => %peer_id, &status_message);
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor
                        .send_status_message(peer_id, status_message),
                )
            }
            Response::BlocksByRange(beacon_block) => {
                self.on_blocks_by_range_response(peer_id, request_id, beacon_block);
            }
            Response::BlocksByRoot(beacon_block) => {
                self.on_blocks_by_root_response(peer_id, request_id, beacon_block);
            }
            Response::BlobsByRange(blob) => {
                self.on_blobs_by_range_response(peer_id, request_id, blob);
            }
            Response::BlobsByRoot(blob) => {
                self.on_blobs_by_root_response(peer_id, request_id, blob);
            }
            Response::DataColumnsByRoot(data_column) => {
                self.on_data_columns_by_root_response(peer_id, request_id, data_column);
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
        message_id: MessageId,
        peer_id: PeerId,
        gossip_message: PubsubMessage<T::EthSpec>,
        should_process: bool,
    ) {
        match gossip_message {
            PubsubMessage::AggregateAndProofAttestation(aggregate_and_proof) => self
                .handle_beacon_processor_send_result(
                    self.network_beacon_processor.send_aggregated_attestation(
                        message_id,
                        peer_id,
                        *aggregate_and_proof,
                        timestamp_now(),
                    ),
                ),
            PubsubMessage::Attestation(subnet_attestation) => self
                .handle_beacon_processor_send_result(
                    self.network_beacon_processor.send_unaggregated_attestation(
                        message_id,
                        peer_id,
                        subnet_attestation.1,
                        subnet_attestation.0,
                        should_process,
                        timestamp_now(),
                    ),
                ),
            PubsubMessage::BeaconBlock(block) => self.handle_beacon_processor_send_result(
                self.network_beacon_processor.send_gossip_beacon_block(
                    message_id,
                    peer_id,
                    self.network_globals.client(&peer_id),
                    block,
                    timestamp_now(),
                ),
            ),
            PubsubMessage::BlobSidecar(data) => {
                let (blob_index, blob_sidecar) = *data;
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor.send_gossip_blob_sidecar(
                        message_id,
                        peer_id,
                        self.network_globals.client(&peer_id),
                        blob_index,
                        blob_sidecar,
                        timestamp_now(),
                    ),
                )
            }
            PubsubMessage::DataColumnSidecar(data) => {
                let (subnet_id, column_sidecar) = *data;
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor
                        .send_gossip_data_column_sidecar(
                            message_id,
                            peer_id,
                            self.network_globals.client(&peer_id),
                            subnet_id,
                            column_sidecar,
                            timestamp_now(),
                        ),
                )
            }
            PubsubMessage::VoluntaryExit(exit) => {
                debug!(self.log, "Received a voluntary exit"; "peer_id" => %peer_id);
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor
                        .send_gossip_voluntary_exit(message_id, peer_id, exit),
                )
            }
            PubsubMessage::ProposerSlashing(proposer_slashing) => {
                debug!(
                    self.log,
                    "Received a proposer slashing";
                    "peer_id" => %peer_id
                );
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor.send_gossip_proposer_slashing(
                        message_id,
                        peer_id,
                        proposer_slashing,
                    ),
                )
            }
            PubsubMessage::AttesterSlashing(attester_slashing) => {
                debug!(
                    self.log,
                    "Received a attester slashing";
                    "peer_id" => %peer_id
                );
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor.send_gossip_attester_slashing(
                        message_id,
                        peer_id,
                        attester_slashing,
                    ),
                )
            }
            PubsubMessage::SignedContributionAndProof(contribution_and_proof) => {
                trace!(
                    self.log,
                    "Received sync committee aggregate";
                    "peer_id" => %peer_id
                );
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor.send_gossip_sync_contribution(
                        message_id,
                        peer_id,
                        *contribution_and_proof,
                        timestamp_now(),
                    ),
                )
            }
            PubsubMessage::SyncCommitteeMessage(sync_committtee_msg) => {
                trace!(
                    self.log,
                    "Received sync committee signature";
                    "peer_id" => %peer_id
                );
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor.send_gossip_sync_signature(
                        message_id,
                        peer_id,
                        sync_committtee_msg.1,
                        sync_committtee_msg.0,
                        timestamp_now(),
                    ),
                )
            }
            PubsubMessage::LightClientFinalityUpdate(light_client_finality_update) => {
                trace!(
                    self.log,
                    "Received light client finality update";
                    "peer_id" => %peer_id
                );
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor
                        .send_gossip_light_client_finality_update(
                            message_id,
                            peer_id,
                            *light_client_finality_update,
                            timestamp_now(),
                        ),
                )
            }
            PubsubMessage::LightClientOptimisticUpdate(light_client_optimistic_update) => {
                trace!(
                    self.log,
                    "Received light client optimistic update";
                    "peer_id" => %peer_id
                );
                self.handle_beacon_processor_send_result(
                    self.network_beacon_processor
                        .send_gossip_light_client_optimistic_update(
                            message_id,
                            peer_id,
                            *light_client_optimistic_update,
                            timestamp_now(),
                        ),
                )
            }
            PubsubMessage::BlsToExecutionChange(bls_to_execution_change) => self
                .handle_beacon_processor_send_result(
                    self.network_beacon_processor
                        .send_gossip_bls_to_execution_change(
                            message_id,
                            peer_id,
                            bls_to_execution_change,
                        ),
                ),
        }
    }

    fn send_status(&mut self, peer_id: PeerId) {
        let status_message = status_message(&self.chain);
        debug!(self.log, "Sending Status Request"; "peer" => %peer_id, &status_message);
        self.network
            .send_processor_request(peer_id, Request::Status(status_message));
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

    /// An error occurred during an RPC request. The state is maintained by the sync manager, so
    /// this function notifies the sync manager of the error.
    pub fn on_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId, error: RPCError) {
        // Check if the failed RPC belongs to sync
        if let RequestId::Sync(request_id) = request_id {
            self.send_to_sync(SyncMessage::RpcError {
                peer_id,
                request_id,
                error,
            });
        }
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

        self.handle_beacon_processor_send_result(
            self.network_beacon_processor
                .send_status_message(peer_id, status),
        )
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
                SyncId::SingleBlock { .. }
                | SyncId::SingleBlob { .. }
                | SyncId::SingleDataColumn { .. }
                | SyncId::ParentLookup { .. }
                | SyncId::ParentLookupBlob { .. }
                | SyncId::ParentLookupDataColumn { .. } => {
                    crit!(self.log, "Block lookups do not request BBRange requests"; "peer_id" => %peer_id);
                    return;
                }
                id @ (SyncId::BackFillBlocks { .. }
                | SyncId::RangeBlocks { .. }
                | SyncId::BackFillBlockAndBlobs { .. }
                | SyncId::RangeBlockAndBlobs { .. }) => id,
            },
            RequestId::Router => {
                crit!(self.log, "All BBRange requests belong to sync"; "peer_id" => %peer_id);
                return;
            }
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

    pub fn on_blobs_by_range_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        blob_sidecar: Option<Arc<BlobSidecar<T::EthSpec>>>,
    ) {
        trace!(
            self.log,
            "Received BlobsByRange Response";
            "peer" => %peer_id,
        );

        if let RequestId::Sync(id) = request_id {
            self.send_to_sync(SyncMessage::RpcBlob {
                peer_id,
                request_id: id,
                blob_sidecar,
                seen_timestamp: timestamp_now(),
            });
        } else {
            crit!(
                self.log,
                "All blobs by range responses should belong to sync"
            );
        }
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
                SyncId::BackFillBlocks { .. }
                | SyncId::RangeBlocks { .. }
                | SyncId::RangeBlockAndBlobs { .. }
                | SyncId::BackFillBlockAndBlobs { .. } => {
                    crit!(self.log, "Batch syncing do not request BBRoot requests"; "peer_id" => %peer_id);
                    return;
                }
                SyncId::SingleBlob { .. } | SyncId::ParentLookupBlob { .. } => {
                    crit!(self.log, "Blob response to block by roots request"; "peer_id" => %peer_id);
                    return;
                }
                SyncId::SingleDataColumn { .. } | SyncId::ParentLookupDataColumn { .. } => {
                    crit!(self.log, "Data column response to block by roots request"; "peer_id" => %peer_id);
                    return;
                }
            },
            RequestId::Router => {
                crit!(self.log, "All BBRoot requests belong to sync"; "peer_id" => %peer_id);
                return;
            }
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

    /// Handle a `BlobsByRoot` response from the peer.
    pub fn on_blobs_by_root_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        blob_sidecar: Option<Arc<BlobSidecar<T::EthSpec>>>,
    ) {
        let request_id = match request_id {
            RequestId::Sync(sync_id) => match sync_id {
                id @ (SyncId::SingleBlob { .. } | SyncId::ParentLookupBlob { .. }) => id,
                SyncId::SingleBlock { .. } | SyncId::ParentLookup { .. } => {
                    crit!(self.log, "Block response to blobs by roots request"; "peer_id" => %peer_id);
                    return;
                }
                SyncId::SingleDataColumn { .. } | SyncId::ParentLookupDataColumn { .. } => {
                    crit!(self.log, "Data column response to blobs by roots request"; "peer_id" => %peer_id);
                    return;
                }
                SyncId::BackFillBlocks { .. }
                | SyncId::RangeBlocks { .. }
                | SyncId::RangeBlockAndBlobs { .. }
                | SyncId::BackFillBlockAndBlobs { .. } => {
                    crit!(self.log, "Batch syncing does not request BBRoot requests"; "peer_id" => %peer_id);
                    return;
                }
            },
            RequestId::Router => {
                crit!(self.log, "All BlobsByRoot requests belong to sync"; "peer_id" => %peer_id);
                return;
            }
        };

        trace!(
            self.log,
            "Received BlobsByRoot Response";
            "peer" => %peer_id,
        );
        self.send_to_sync(SyncMessage::RpcBlob {
            request_id,
            peer_id,
            blob_sidecar,
            seen_timestamp: timestamp_now(),
        });
    }

    /// Handle a `DataColumnsByRoot` response from the peer.
    pub fn on_data_columns_by_root_response(
        &mut self,
        _peer_id: PeerId,
        _request_id: RequestId,
        _data_column_sidecar: Option<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) {
        // TODO(das) implement `DataColumnsByRoot` response handling
    }

    fn handle_beacon_processor_send_result(
        &mut self,
        result: Result<(), crate::network_beacon_processor::Error<T::EthSpec>>,
    ) {
        if let Err(e) = result {
            let work_type = match &e {
                mpsc::error::TrySendError::Closed(work) | mpsc::error::TrySendError::Full(work) => {
                    work.work_type()
                }
            };

            if self.logger_debounce.elapsed() {
                error!(&self.log, "Unable to send message to the beacon processor";
                    "error" => %e, "type" => work_type)
            }
        }
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
