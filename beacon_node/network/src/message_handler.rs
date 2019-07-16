use crate::error;
use crate::service::{NetworkMessage, OutgoingMessage};
use crate::sync::SimpleSync;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::{
    behaviour::PubsubMessage,
    rpc::{RPCError, RPCErrorResponse, RPCRequest, RPCResponse, RequestId},
    PeerId, RPCEvent,
};
use futures::future::Future;
use futures::stream::Stream;
use slog::{debug, error, warn};
use ssz::Decode;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler<T: BeaconChainTypes> {
    /// Currently loaded and initialised beacon chain.
    _chain: Arc<BeaconChain<T>>,
    /// The syncing framework.
    sync: SimpleSync<T>,
    /// The context required to send messages to, and process messages from peers.
    network_context: NetworkContext,
    /// The `MessageHandler` logger.
    log: slog::Logger,
}

/// Types of messages the handler can receive.
#[derive(Debug)]
pub enum HandlerMessage {
    /// We have initiated a connection to a new peer.
    PeerDialed(PeerId),
    /// Peer has disconnected,
    PeerDisconnected(PeerId),
    /// An RPC response/request has been received.
    RPC(PeerId, RPCEvent),
    /// A gossip message has been received.
    PubsubMessage(PeerId, Box<PubsubMessage>),
}

impl<T: BeaconChainTypes + 'static> MessageHandler<T> {
    /// Initializes and runs the MessageHandler.
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_send: mpsc::UnboundedSender<NetworkMessage>,
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<HandlerMessage>> {
        debug!(log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();

        // Initialise sync and begin processing in thread
        // generate the Message handler
        let sync = SimpleSync::new(beacon_chain.clone(), &log);

        let mut handler = MessageHandler {
            _chain: beacon_chain.clone(),
            sync,
            network_context: NetworkContext::new(network_send, log.clone()),
            log: log.clone(),
        };

        // spawn handler task
        // TODO: Handle manual termination of thread
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
    fn handle_message(&mut self, message: HandlerMessage) {
        match message {
            // we have initiated a connection to a peer
            HandlerMessage::PeerDialed(peer_id) => {
                self.sync.on_connect(peer_id, &mut self.network_context);
            }
            // A peer has disconnected
            HandlerMessage::PeerDisconnected(peer_id) => {
                self.sync.on_disconnect(peer_id);
            }
            // we have received an RPC message request/response
            HandlerMessage::RPC(peer_id, rpc_event) => {
                self.handle_rpc_message(peer_id, rpc_event);
            }
            // we have received an RPC message request/response
            HandlerMessage::PubsubMessage(peer_id, gossip) => {
                self.handle_gossip(peer_id, *gossip);
            }
            //TODO: Handle all messages
            _ => {}
        }
    }

    /* RPC - Related functionality */

    /// Handle RPC messages
    fn handle_rpc_message(&mut self, peer_id: PeerId, rpc_message: RPCEvent) {
        match rpc_message {
            RPCEvent::Request(id, req) => self.handle_rpc_request(peer_id, id, req),
            RPCEvent::Response(id, resp) => self.handle_rpc_response(peer_id, id, resp),
            RPCEvent::Error(id, error) => self.handle_rpc_error(peer_id, id, error),
        }
    }

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, request_id: RequestId, request: RPCRequest) {
        // TODO: process the `id`.
        match request {
            RPCRequest::Hello(hello_message) => self.sync.on_hello_request(
                peer_id,
                request_id,
                hello_message,
                &mut self.network_context,
            ),
            RPCRequest::Goodbye(goodbye_reason) => self.sync.on_goodbye(peer_id, goodbye_reason),
            RPCRequest::BeaconBlockRoots(request) => self.sync.on_beacon_block_roots_request(
                peer_id,
                request_id,
                request,
                &mut self.network_context,
            ),
            RPCRequest::BeaconBlockHeaders(request) => self.sync.on_beacon_block_headers_request(
                peer_id,
                request_id,
                request,
                &mut self.network_context,
            ),
            RPCRequest::BeaconBlockBodies(request) => self.sync.on_beacon_block_bodies_request(
                peer_id,
                request_id,
                request,
                &mut self.network_context,
            ),
            RPCRequest::BeaconChainState(_) => {
                // We do not implement this endpoint, it is not required and will only likely be
                // useful for light-client support in later phases.
                warn!(self.log, "BeaconChainState RPC call is not supported.");
            }
        }
    }

    /// An RPC response has been received from the network.
    // we match on id and ignore responses past the timeout.
    fn handle_rpc_response(
        &mut self,
        peer_id: PeerId,
        id: RequestId,
        error_response: RPCErrorResponse,
    ) {
        //TODO: Potentially do not need to keep track of this at all. This has all been shifted
        //into libp2p stack. Tracking Id's will only be necessary if a response is important
        //relative to a specific request. Note: BeaconBlockBodies already returns with the data
        //associated with its request.
        // Currently leave this here for testing, to ensure it is redundant.
        if self
            .network_context
            .outstanding_outgoing_request_ids
            .remove(&(peer_id.clone(), id))
            .is_none()
        {
            // This should never happen. The RPC layer handles all timeouts and ensures a response
            // matches a request.
            debug_assert!(false);

            error!(
                self.log,
                "Unknown ResponseId for incoming RPCRequest";
                "peer" => format!("{:?}", peer_id),
                "request_id" => format!("{}", id)
            );
            return;
        }

        // an error could have occurred.
        // TODO: Handle Error gracefully
        match error_response {
            RPCErrorResponse::EncodingError => {
                warn!(self.log, "Encoding Error"; "peer" => format!("{:?}", peer_id), "request_id" => format!("{}",id))
            }
            RPCErrorResponse::InvalidRequest(error) => {
                warn!(self.log, "";"peer" => format!("{:?}", peer_id), "Invalid Request" => error.as_string())
            }
            RPCErrorResponse::ServerError(error) => {
                warn!(self.log, "";"peer" => format!("{:?}", peer_id), "Server Error" => error.as_string())
            }
            RPCErrorResponse::Unknown(error) => {
                warn!(self.log, "";"peer" => format!("{:?}", peer_id), "Unknown Error" => error.as_string())
            }
            RPCErrorResponse::Success(response) => {
                match response {
                    RPCResponse::Hello(hello_message) => {
                        self.sync.on_hello_response(
                            peer_id,
                            hello_message,
                            &mut self.network_context,
                        );
                    }
                    RPCResponse::BeaconBlockRoots(response) => {
                        self.sync.on_beacon_block_roots_response(
                            peer_id,
                            response,
                            &mut self.network_context,
                        );
                    }
                    RPCResponse::BeaconBlockHeaders(response) => {
                        if let Some(decoded_block_headers) = self.decode_block_headers(response) {
                            self.sync.on_beacon_block_headers_response(
                                peer_id,
                                decoded_block_headers,
                                &mut self.network_context,
                            );
                        } else {
                            warn!(self.log, "Peer sent invalid block headers";"peer" => format!("{:?}", peer_id))
                        }
                    }
                    RPCResponse::BeaconBlockBodies(response) => {
                        if let Some(decoded_block_bodies) = self.decode_block_bodies(response) {
                            self.sync.on_beacon_block_bodies_response(
                                peer_id,
                                decoded_block_bodies,
                                &mut self.network_context,
                            );
                        } else {
                            warn!(self.log, "Peer sent invalid block bodies";"peer" => format!("{:?}", peer_id))
                        }
                    }
                    RPCResponse::BeaconChainState(_) => {
                        // We do not implement this endpoint, it is not required and will only likely be
                        // useful for light-client support in later phases.
                        //
                        // Theoretically, we shouldn't reach this code because we should never send a
                        // beacon state RPC request.
                        warn!(self.log, "BeaconChainState RPC call is not supported.");
                    }
                }
            }
        }
    }

    /// Verifies and decodes the ssz-encoded block bodies received from peers.
    fn decode_block_bodies(
        &self,
        bodies_response: BeaconBlockBodiesResponse,
    ) -> Option<DecodedBeaconBlockBodiesResponse> {
        //TODO: Implement faster block verification before decoding entirely
        let simple_decoded_bodies =
            EncodeableBeaconBlockBodiesResponse::from_ssz_bytes(&bodies_response.block_bodies);

        //TODO: Potentially improve the types used here for SSZ encoding/decoding
        if let Ok(simple_decoded_bodies) = simple_decoded_bodies {
            Some(DecodedBeaconBlockBodiesResponse {
                block_roots: bodies_response
                    .block_roots
                    .expect("Responses must have associated roots"),
                block_bodies: simple_decoded_bodies.block_bodies,
            })
        } else {
            None
        }
    }

    /// Verifies and decodes the ssz-encoded block headers received from peers.
    fn decode_block_headers(
        &self,
        headers_response: BeaconBlockHeadersResponse,
    ) -> Option<EncodeableBeaconBlockHeadersResponse> {
        //TODO: Implement faster header verification before decoding entirely
        EncodeableBeaconBlockHeadersResponse::from_ssz_bytes(&headers_response.headers).ok()
    }

    /// Handle various RPC errors
    fn handle_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId, error: RPCError) {
        //TODO: Handle error correctly
        warn!(self.log, "RPC Error"; "Peer" => format!("{:?}", peer_id), "Request Id" => format!("{}", request_id), "Error" => format!("{:?}", error));
    }

    /// Handle RPC messages
    fn handle_gossip(&mut self, peer_id: PeerId, gossip_message: PubsubMessage) {
        match gossip_message {
            PubsubMessage::Block(message) => {
                let _should_foward_on =
                    self.sync
                        .on_block_gossip(peer_id, message, &mut self.network_context);
            }
            PubsubMessage::Attestation(message) => {
                self.sync
                    .on_attestation_gossip(peer_id, message, &mut self.network_context)
            }
        }
    }
}

pub struct NetworkContext {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage>,
    /// A mapping of peers and the RPC id we have sent an RPC request to.
    outstanding_outgoing_request_ids: HashMap<(PeerId, RequestId), Instant>,
    /// Stores the next `RequestId` we should include on an outgoing `RPCRequest` to a `PeerId`.
    outgoing_request_ids: HashMap<PeerId, RequestId>,
    /// The `MessageHandler` logger.
    log: slog::Logger,
}

impl NetworkContext {
    pub fn new(network_send: mpsc::UnboundedSender<NetworkMessage>, log: slog::Logger) -> Self {
        Self {
            network_send,
            outstanding_outgoing_request_ids: HashMap::new(),
            outgoing_request_ids: HashMap::new(),
            log,
        }
    }

    pub fn disconnect(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.send_rpc_request(peer_id, RPCRequest::Goodbye(reason))
        // TODO: disconnect peers.
    }

    pub fn send_rpc_request(&mut self, peer_id: PeerId, rpc_request: RPCRequest) {
        let id = self.generate_request_id(&peer_id);

        self.outstanding_outgoing_request_ids
            .insert((peer_id.clone(), id), Instant::now());

        self.send_rpc_event(peer_id, RPCEvent::Request(id, rpc_request));
    }

    //TODO: Handle Error responses
    pub fn send_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        rpc_response: RPCResponse,
    ) {
        self.send_rpc_event(
            peer_id,
            RPCEvent::Response(request_id, RPCErrorResponse::Success(rpc_response)),
        );
    }

    fn send_rpc_event(&mut self, peer_id: PeerId, rpc_event: RPCEvent) {
        self.send(peer_id, OutgoingMessage::RPC(rpc_event))
    }

    fn send(&mut self, peer_id: PeerId, outgoing_message: OutgoingMessage) {
        self.network_send
            .try_send(NetworkMessage::Send(peer_id, outgoing_message))
            .unwrap_or_else(|_| {
                warn!(
                    self.log,
                    "Could not send RPC message to the network service"
                )
            });
    }

    /// Returns the next `RequestId` for sending an `RPCRequest` to the `peer_id`.
    fn generate_request_id(&mut self, peer_id: &PeerId) -> RequestId {
        let next_id = self
            .outgoing_request_ids
            .entry(peer_id.clone())
            .and_modify(|id| *id += 1)
            .or_insert_with(|| 0);

        *next_id
    }
}
