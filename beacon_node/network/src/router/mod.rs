//! This module handles incoming network messages.
//!
//! It routes the messages to appropriate services, such as the Sync
//! and processes those that are
#![allow(clippy::unit_arg)]

pub mod processor;

use crate::error;
use crate::service::NetworkMessage;
use beacon_chain::{AttestationType, BeaconChain, BeaconChainTypes};
use eth2_libp2p::{
    rpc::{RPCError, RPCErrorResponse, RPCRequest, RPCResponse, RequestId, ResponseTermination},
    MessageId, NetworkGlobals, PeerId, PubsubMessage, RPCEvent,
};
use futures::future::Future;
use futures::stream::Stream;
use processor::Processor;
use slog::{debug, o, trace, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::EthSpec;

/// Handles messages received from the network and client and organises syncing. This
/// functionality of this struct is to validate an decode messages from the network before
/// passing them to the internal message processor. The message processor spawns a syncing thread
/// which manages which blocks need to be requested and processed.
pub struct Router<T: BeaconChainTypes> {
    /// A channel to the network service to allow for gossip propagation.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    /// Processes validated and decoded messages from the network. Has direct access to the
    /// sync manager.
    processor: Processor<T>,
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
    /// An RPC response/request has been received.
    RPC(PeerId, RPCEvent<T>),
    /// A gossip message has been received. The fields are: message id, the peer that sent us this
    /// message and the message itself.
    PubsubMessage(MessageId, PeerId, PubsubMessage<T>),
    /// The peer manager has requested we re-status a peer.
    StatusPeer(PeerId),
}

impl<T: BeaconChainTypes> Router<T> {
    /// Initializes and runs the Router.
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<RouterMessage<T::EthSpec>>> {
        let message_handler_log = log.new(o!("service"=> "router"));
        trace!(message_handler_log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();

        // Initialise a message instance, which itself spawns the syncing thread.
        let processor = Processor::new(
            executor,
            beacon_chain,
            network_globals,
            network_send.clone(),
            &log,
        );

        // generate the Message handler
        let mut handler = Router {
            network_send,
            processor,
            log: message_handler_log,
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(
            handler_recv
                .for_each(move |msg| Ok(handler.handle_message(msg)))
                .map_err(move |_| {
                    debug!(log, "Network message handler terminated.");
                }),
        );

        Ok(handler_send)
    }

    /// Handle all messages incoming from the network service.
    fn handle_message(&mut self, message: RouterMessage<T::EthSpec>) {
        match message {
            // we have initiated a connection to a peer or the peer manager has requested a
            // re-status
            RouterMessage::PeerDialed(peer_id) | RouterMessage::StatusPeer(peer_id) => {
                self.processor.send_status(peer_id);
            }
            // A peer has disconnected
            RouterMessage::PeerDisconnected(peer_id) => {
                self.processor.on_disconnect(peer_id);
            }
            // An RPC message request/response has been received
            RouterMessage::RPC(peer_id, rpc_event) => {
                self.handle_rpc_message(peer_id, rpc_event);
            }
            // An RPC message request/response has been received
            RouterMessage::PubsubMessage(id, peer_id, gossip) => {
                self.handle_gossip(id, peer_id, gossip);
            }
        }
    }

    /* RPC - Related functionality */

    /// Handle RPC messages
    fn handle_rpc_message(&mut self, peer_id: PeerId, rpc_message: RPCEvent<T::EthSpec>) {
        match rpc_message {
            RPCEvent::Request(id, req) => self.handle_rpc_request(peer_id, id, req),
            RPCEvent::Response(id, resp) => self.handle_rpc_response(peer_id, id, resp),
            RPCEvent::Error(id, error) => self.handle_rpc_error(peer_id, id, error),
        }
    }

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        request: RPCRequest<T::EthSpec>,
    ) {
        match request {
            RPCRequest::Status(status_message) => {
                self.processor
                    .on_status_request(peer_id, request_id, status_message)
            }
            RPCRequest::Goodbye(goodbye_reason) => {
                debug!(
                    self.log, "PeerGoodbye";
                    "peer" => format!("{:?}", peer_id),
                    "reason" => format!("{:?}", goodbye_reason),
                );
                self.processor.on_disconnect(peer_id);
            }
            RPCRequest::BlocksByRange(request) => self
                .processor
                .on_blocks_by_range_request(peer_id, request_id, request),
            RPCRequest::BlocksByRoot(request) => self
                .processor
                .on_blocks_by_root_request(peer_id, request_id, request),
            RPCRequest::Ping(_) => unreachable!("Ping MUST be handled in the behaviour"),
            RPCRequest::MetaData(_) => unreachable!("MetaData MUST be handled in the behaviour"),
        }
    }

    /// An RPC response has been received from the network.
    // we match on id and ignore responses past the timeout.
    fn handle_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        error_response: RPCErrorResponse<T::EthSpec>,
    ) {
        // an error could have occurred.
        match error_response {
            RPCErrorResponse::InvalidRequest(error) => {
                warn!(self.log, "Peer indicated invalid request";"peer_id" => format!("{:?}", peer_id), "error" => error.as_string());
                self.handle_rpc_error(peer_id, request_id, RPCError::RPCErrorResponse);
            }
            RPCErrorResponse::ServerError(error) => {
                warn!(self.log, "Peer internal server error";"peer_id" => format!("{:?}", peer_id), "error" => error.as_string());
                self.handle_rpc_error(peer_id, request_id, RPCError::RPCErrorResponse);
            }
            RPCErrorResponse::Unknown(error) => {
                warn!(self.log, "Unknown peer error";"peer" => format!("{:?}", peer_id), "error" => error.as_string());
                self.handle_rpc_error(peer_id, request_id, RPCError::RPCErrorResponse);
            }
            RPCErrorResponse::Success(response) => match response {
                RPCResponse::Status(status_message) => {
                    self.processor.on_status_response(peer_id, status_message);
                }
                RPCResponse::BlocksByRange(beacon_block) => {
                    self.processor.on_blocks_by_range_response(
                        peer_id,
                        request_id,
                        Some(beacon_block),
                    );
                }
                RPCResponse::BlocksByRoot(beacon_block) => {
                    self.processor.on_blocks_by_root_response(
                        peer_id,
                        request_id,
                        Some(beacon_block),
                    );
                }
                RPCResponse::Pong(_) => {
                    unreachable!("Ping must be handled in the behaviour");
                }
                RPCResponse::MetaData(_) => {
                    unreachable!("Meta data must be handled in the behaviour");
                }
            },
            RPCErrorResponse::StreamTermination(response_type) => {
                // have received a stream termination, notify the processing functions
                match response_type {
                    ResponseTermination::BlocksByRange => {
                        self.processor
                            .on_blocks_by_range_response(peer_id, request_id, None);
                    }
                    ResponseTermination::BlocksByRoot => {
                        self.processor
                            .on_blocks_by_root_response(peer_id, request_id, None);
                    }
                }
            }
        }
    }

    /// Handle various RPC errors
    fn handle_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId, error: RPCError) {
        warn!(self.log, "RPC Error"; "Peer" => format!("{:?}", peer_id), "request_id" => format!("{}", request_id), "Error" => format!("{:?}", error));
        self.processor.on_rpc_error(peer_id, request_id);
    }

    /// Handle RPC messages
    fn handle_gossip(
        &mut self,
        id: MessageId,
        peer_id: PeerId,
        gossip_message: PubsubMessage<T::EthSpec>,
    ) {
        match gossip_message {
            // Attestations should never reach the router.
            PubsubMessage::AggregateAndProofAttestation(aggregate_and_proof) => {
                if self
                    .processor
                    .should_forward_aggregate_attestation(&aggregate_and_proof)
                {
                    self.propagate_message(id, peer_id.clone());
                }
                self.processor.process_attestation_gossip(
                    peer_id,
                    aggregate_and_proof.message.aggregate,
                    AttestationType::Aggregated,
                );
            }
            PubsubMessage::Attestation(subnet_attestation) => {
                if self
                    .processor
                    .should_forward_attestation(&subnet_attestation.1)
                {
                    self.propagate_message(id, peer_id.clone());
                }
                self.processor.process_attestation_gossip(
                    peer_id,
                    subnet_attestation.1,
                    AttestationType::Unaggregated { should_store: true },
                );
            }
            PubsubMessage::BeaconBlock(block) => {
                match self.processor.should_forward_block(&peer_id, block) {
                    Ok(verified_block) => {
                        self.propagate_message(id, peer_id.clone());
                        self.processor.on_block_gossip(peer_id, verified_block);
                    }
                    Err(e) => {
                        warn!(self.log, "Could not verify block for gossip";
                            "error" => format!("{:?}", e));
                    }
                }
            }
            PubsubMessage::VoluntaryExit(_exit) => {
                // TODO: Apply more sophisticated validation
                self.propagate_message(id, peer_id.clone());
                // TODO: Handle exits
                debug!(self.log, "Received a voluntary exit"; "peer_id" => format!("{}", peer_id) );
            }
            PubsubMessage::ProposerSlashing(_proposer_slashing) => {
                // TODO: Apply more sophisticated validation
                self.propagate_message(id, peer_id.clone());
                // TODO: Handle proposer slashings
                debug!(self.log, "Received a proposer slashing"; "peer_id" => format!("{}", peer_id) );
            }
            PubsubMessage::AttesterSlashing(_attester_slashing) => {
                // TODO: Apply more sophisticated validation
                self.propagate_message(id, peer_id.clone());
                // TODO: Handle attester slashings
                debug!(self.log, "Received an attester slashing"; "peer_id" => format!("{}", peer_id) );
            }
        }
    }

    /// Informs the network service that the message should be forwarded to other peers.
    fn propagate_message(&mut self, message_id: MessageId, propagation_source: PeerId) {
        self.network_send
            .try_send(NetworkMessage::Propagate {
                propagation_source,
                message_id,
            })
            .unwrap_or_else(|_| {
                warn!(
                    self.log,
                    "Could not send propagation request to the network service"
                )
            });
    }
}
