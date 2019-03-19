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
    PeerId, RPCEvent,
};
use slog::debug;
use slog::warn;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::Hash256;

/// Timeout for RPC requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler {
    /// Currently loaded and initialised beacon chain.
    chain: Arc<BeaconChain>,
    /// The syncing framework.
    sync: SimpleSync,
    /// The network channel to relay messages to the Network service.
    network_send: crossbeam_channel::Sender<NetworkMessage>,
    /// A mapping of peers we have sent an RPC request to.
    requests: HashMap<PeerId, Vec<RPCRequestInfo>>,
    /// A counter of request id for each peer.
    request_ids: HashMap<PeerId, u64>,
    /// The `MessageHandler` logger.
    log: slog::Logger,
}

/// RPC request information
pub struct RPCRequestInfo {
    /// The id of the request
    id: u64,
    /// The time the request was sent, to check ttl.
    request_time: Instant,
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
    RPC(RPCEvent),
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
            HandlerMessage::PeerDialed(peer_id) => {
                self.send_hello_request(peer_id);
            }
            //TODO: Handle all messages
            _ => {}
        }
    }

    /// Sends a HELLO RPC request to a newly connected peer.
    fn send_hello_request(&mut self, peer_id: PeerId) {
        // generate a unique id for the peer
        let id = {
            let borrowed_id = self.request_ids.entry(peer_id.clone()).or_insert_with(|| 0);
            let id = borrowed_id.clone();
            //increment the counter
            *borrowed_id += 1;
            id
        };
        // register RPC request
        {
            let requests = self
                .requests
                .entry(peer_id.clone())
                .or_insert_with(|| vec![]);
            requests.push(RPCRequestInfo {
                id: id.clone(),
                request_time: Instant::now(),
            });
        }

        // build the rpc request
        let rpc_event = RPCEvent::Request {
            id,
            method_id: RPCMethod::Hello.into(),
            body: RPCRequest::Hello(self.sync.generate_hello()),
        };

        // send the hello request to the network
        self.send_rpc(peer_id, rpc_event);
    }

    /// Sends and RPC response
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
