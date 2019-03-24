use crate::beacon_chain::BeaconChain;
use crate::error;
use crate::service::{NetworkMessage, OutgoingMessage};
use crate::sync::SimpleSync;
use crossbeam_channel::{unbounded as channel, Sender};
use eth2_libp2p::{
    rpc::{RPCRequest, RPCResponse},
    PeerId, RPCEvent,
};
use futures::future;
use slog::debug;
use slog::warn;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Timeout for RPC requests.
// const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout before banning a peer for non-identification.
// const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler {
    /// Currently loaded and initialised beacon chain.
    _chain: Arc<BeaconChain>,
    /// The syncing framework.
    sync: SimpleSync,
    /// The context required to send messages to, and process messages from peers.
    network_context: NetworkContext,
    /// The `MessageHandler` logger.
    log: slog::Logger,
}

/// Types of messages the handler can receive.
#[derive(Debug, Clone)]
pub enum HandlerMessage {
    /// We have initiated a connection to a new peer.
    PeerDialed(PeerId),
    /// Peer has disconnected,
    PeerDisconnected(PeerId),
    /// An RPC response/request has been received.
    RPC(PeerId, RPCEvent),
    /// A block has been imported.
    BlockImported(), //TODO: This comes from pub-sub - decide its contents
}

impl MessageHandler {
    /// Initializes and runs the MessageHandler.
    pub fn spawn(
        beacon_chain: Arc<BeaconChain>,
        network_send: crossbeam_channel::Sender<NetworkMessage>,
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<Sender<HandlerMessage>> {
        debug!(log, "Service starting");

        let (handler_send, handler_recv) = channel();

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
        executor.spawn(future::poll_fn(move || -> Result<_, _> {
            loop {
                handler.handle_message(handler_recv.recv().map_err(|_| {
                    debug!(log, "Network message handler terminated.");
                })?);
            }
        }));

        Ok(handler_send)
    }

    /// Handle all messages incoming from the network service.
    fn handle_message(&mut self, message: HandlerMessage) {
        match message {
            // we have initiated a connection to a peer
            HandlerMessage::PeerDialed(peer_id) => {
                self.sync.on_connect(peer_id, &mut self.network_context);
            }
            // we have received an RPC message request/response
            HandlerMessage::RPC(peer_id, rpc_event) => {
                self.handle_rpc_message(peer_id, rpc_event);
            }
            //TODO: Handle all messages
            _ => {}
        }
    }

    /* RPC - Related functionality */

    /// Handle RPC messages
    fn handle_rpc_message(&mut self, peer_id: PeerId, rpc_message: RPCEvent) {
        match rpc_message {
            RPCEvent::Request { id, body, .. // TODO: Clean up RPC Message types, have a cleaner type by this point.
            } => self.handle_rpc_request(peer_id, id, body),
            RPCEvent::Response { id, result, .. } => self.handle_rpc_response(peer_id, id, result),
        }
    }

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, id: u64, request: RPCRequest) {
        // TODO: ensure the id is legit
        match request {
            RPCRequest::Hello(hello_message) => {
                self.sync
                    .on_hello_request(peer_id, hello_message, &mut self.network_context)
            }
            RPCRequest::BeaconBlockRoots(request) => {
                self.sync
                    .on_beacon_block_roots_request(peer_id, request, &mut self.network_context)
            }
            RPCRequest::BeaconBlockHeaders(request) => self.sync.on_beacon_block_headers_request(
                peer_id,
                request,
                &mut self.network_context,
            ),
            RPCRequest::BeaconBlockBodies(request) => self.sync.on_beacon_block_bodies_request(
                peer_id,
                request,
                &mut self.network_context,
            ),
            // TODO: Handle all requests
            _ => panic!("Unknown request: {:?}", request),
        }
    }

    /// An RPC response has been received from the network.
    // we match on id and ignore responses past the timeout.
    fn handle_rpc_response(&mut self, peer_id: PeerId, id: u64, response: RPCResponse) {
        // if response id is related to a request, ignore (likely RPC timeout)
        if self
            .network_context
            .requests
            .remove(&(peer_id.clone(), id))
            .is_none()
        {
            debug!(self.log, "Unrecognized response from peer: {:?}", peer_id);
            return;
        }
        let response_str = match response {
            RPCResponse::Hello(hello_message) => {
                self.sync
                    .on_hello_response(peer_id, hello_message, &mut self.network_context);
                "Hello"
            }
            RPCResponse::BeaconBlockRoots(response) => {
                self.sync.on_beacon_block_roots_response(
                    peer_id,
                    response,
                    &mut self.network_context,
                );
                "BeaconBlockRoots"
            }
            RPCResponse::BeaconBlockHeaders(response) => {
                self.sync.on_beacon_block_headers_response(
                    peer_id,
                    response,
                    &mut self.network_context,
                );
                "BeaconBlockHeaders"
            }
            RPCResponse::BeaconBlockBodies(response) => {
                self.sync.on_beacon_block_bodies_response(
                    peer_id,
                    response,
                    &mut self.network_context,
                );
                "BeaconBlockBodies"
            }
            // TODO: Handle all responses
            _ => panic!("Unknown response: {:?}", response),
        };

        debug!(self.log, "RPCResponse"; "type" => response_str);
    }
}

pub struct NetworkContext {
    /// The network channel to relay messages to the Network service.
    network_send: crossbeam_channel::Sender<NetworkMessage>,
    /// A mapping of peers and the RPC id we have sent an RPC request to.
    requests: HashMap<(PeerId, u64), Instant>,
    /// A counter of request id for each peer.
    request_ids: HashMap<PeerId, u64>,
    /// The `MessageHandler` logger.
    log: slog::Logger,
}

impl NetworkContext {
    pub fn new(network_send: crossbeam_channel::Sender<NetworkMessage>, log: slog::Logger) -> Self {
        Self {
            network_send,
            requests: HashMap::new(),
            request_ids: HashMap::new(),
            log,
        }
    }

    pub fn disconnect(&self, _peer_id: PeerId) {
        // TODO: disconnect peers.
    }

    pub fn send_rpc_request(&mut self, peer_id: PeerId, rpc_request: RPCRequest) {
        let id = self.generate_request_id(&peer_id);
        self.send_rpc_event(
            peer_id,
            RPCEvent::Request {
                id,
                method_id: rpc_request.method_id(),
                body: rpc_request,
            },
        );
    }

    pub fn send_rpc_response(&mut self, peer_id: PeerId, rpc_response: RPCResponse) {
        let id = self.generate_request_id(&peer_id);
        self.send_rpc_event(
            peer_id,
            RPCEvent::Response {
                id,
                method_id: rpc_response.method_id(),
                result: rpc_response,
            },
        );
    }

    fn send_rpc_event(&self, peer_id: PeerId, rpc_event: RPCEvent) {
        self.send(peer_id, OutgoingMessage::RPC(rpc_event))
    }

    fn send(&self, peer_id: PeerId, outgoing_message: OutgoingMessage) {
        self.network_send
            .send(NetworkMessage::Send(peer_id, outgoing_message))
            .unwrap_or_else(|_| {
                warn!(
                    self.log,
                    "Could not send RPC message to the network service"
                )
            });
        //
    }

    /// Generates a new request id for a peer.
    fn generate_request_id(&mut self, peer_id: &PeerId) -> u64 {
        // generate a unique id for the peer
        let id = {
            let borrowed_id = self.request_ids.entry(peer_id.clone()).or_insert_with(|| 0);
            let id = borrowed_id.clone();
            //increment the counter
            *borrowed_id += 1;
            id
        };
        // register RPC request
        self.requests.insert((peer_id.clone(), id), Instant::now());
        id
    }
}
