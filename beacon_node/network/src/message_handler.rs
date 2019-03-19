use crate::beacon_chain::BeaconChain;
use crate::error;
use crate::messages::NodeMessage;
use crate::service::{NetworkMessage, OutgoingMessage};
use crate::sync::SimpleSync;
use crossbeam_channel::{unbounded as channel, Sender};
use futures::future;
use futures::prelude::*;
use libp2p::{
    rpc::{RPCMethod, RPCRequest, RPCResponse},
    HelloMessage, PeerId, RPCEvent,
};
use slog::warn;
use slog::{debug, trace};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::Hash256;

/// Timeout for RPC requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout before banning a peer for non-identification.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler {
    /// Currently loaded and initialised beacon chain.
    chain: Arc<BeaconChain>,
    /// The syncing framework.
    sync: SimpleSync,
    /// The network channel to relay messages to the Network service.
    network_send: crossbeam_channel::Sender<NetworkMessage>,
    /// A mapping of peers and the RPC id we have sent an RPC request to.
    requests: HashMap<(PeerId, u64), Instant>,
    /// A counter of request id for each peer.
    request_ids: HashMap<PeerId, u64>,
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
    /// A Node message has been received.
    Message(PeerId, NodeMessage),
    /// An RPC response/request has been received.
    RPC(PeerId, RPCEvent),
}

impl MessageHandler {
    /// Initializes and runs the MessageHandler.
    pub fn new(
        beacon_chain: Arc<BeaconChain>,
        network_send: crossbeam_channel::Sender<NetworkMessage>,
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<Sender<HandlerMessage>> {
        debug!(log, "Service starting");

        let (handler_send, handler_recv) = channel();

        // Initialise sync and begin processing in thread
        // generate the Message handler
        let sync = SimpleSync::new(beacon_chain.clone());

        let mut handler = MessageHandler {
            // TODO: The handler may not need a chain, perhaps only sync?
            chain: beacon_chain.clone(),
            sync,
            network_send,
            requests: HashMap::new(),
            request_ids: HashMap::new(),

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

    fn handle_message(&mut self, message: HandlerMessage) {
        match message {
            // we have initiated a connection to a peer
            HandlerMessage::PeerDialed(peer_id) => {
                let id = self.generate_request_id(&peer_id);
                self.send_hello(peer_id, id, true);
            }
            // we have received an RPC message request/response
            HandlerMessage::RPC(peer_id, rpc_event) => {
                self.handle_rpc_message(peer_id, rpc_event);
            }
            //TODO: Handle all messages
            _ => {}
        }
    }

    fn handle_rpc_message(&mut self, peer_id: PeerId, rpc_message: RPCEvent) {
        match rpc_message {
            RPCEvent::Request {
                id,
                method_id: _, // TODO: Clean up RPC Message types, have a cleaner type by this point.
                body,
            } => self.handle_rpc_request(peer_id, id, body),
            RPCEvent::Response {
                id,
                method_id: _,
                result,
            } => self.handle_rpc_response(peer_id, id, result),
        }
    }

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, id: u64, request: RPCRequest) {
        match request {
            RPCRequest::Hello(hello_message) => {
                self.handle_hello_request(peer_id, id, hello_message)
            }
        }
    }

    /// An RPC response has been received from the network.
    // we match on id and ignore responses past the timeout.
    fn handle_rpc_response(&mut self, peer_id: PeerId, id: u64, response: RPCResponse) {
        // if response id is related to a request, ignore (likely RPC timeout)
        if self.requests.remove(&(peer_id, id)).is_none() {
            return;
        }
    }

    fn handle_hello_request(&mut self, peer_id: PeerId, id: u64, hello_message: HelloMessage) {
        // send back a HELLO message
        self.send_hello(peer_id.clone(), id, false);
        // validate the peer
        if !self.sync.validate_peer(peer_id.clone(), hello_message) {
            debug!(
                self.log,
                "Peer dropped due to mismatching HELLO messages: {:?}", peer_id
            );
            //TODO: block/ban the peer
        }
    }

    fn handle_hello_response(&mut self, peer_id: PeerId, id: u64, response: HelloMessage) {
        debug!(self.log, "Hello response received from peer: {:?}", peer_id);
        // validate peer - decide whether to drop/ban or add to sync
        // TODO: Peer validation
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
        debug!(
            self.log,
            "Hello request registered with peer: {:?}", peer_id
        );
        id
    }

    /// Sends a HELLO RPC request or response to a newly connected peer.
    //TODO: The boolean determines if sending request/respond, will be cleaner in the RPC re-write
    fn send_hello(&mut self, peer_id: PeerId, id: u64, request: bool) {
        let rpc_event = match request {
            true => RPCEvent::Request {
                id,
                method_id: RPCMethod::Hello.into(),
                body: RPCRequest::Hello(self.sync.generate_hello()),
            },
            false => RPCEvent::Response {
                id,
                method_id: RPCMethod::Hello.into(),
                result: RPCResponse::Hello(self.sync.generate_hello()),
            },
        };

        // send the hello request to the network
        trace!(self.log, "Sending HELLO message to peer {:?}", peer_id);
        self.send_rpc(peer_id, rpc_event);
    }

    /// Sends an RPC request/response to the network server.
    fn send_rpc(&self, peer_id: PeerId, rpc_event: RPCEvent) {
        self.network_send
            .send(NetworkMessage::Send(
                peer_id,
                OutgoingMessage::RPC(rpc_event),
            ))
            .unwrap_or_else(|_| {
                warn!(
                    self.log,
                    "Could not send RPC message to the network service"
                )
            });
    }
}
