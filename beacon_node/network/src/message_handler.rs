use crate::beacon_chain::BeaconChain;
use crate::error;
use crate::messages::NodeMessage;
use crate::service::NetworkMessage;
use crossbeam_channel::{unbounded as channel, Sender};
use futures::future;
use futures::prelude::*;
use libp2p::rpc;
use libp2p::{PeerId, RPCEvent};
use slog::debug;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sync::SimpleSync;
use types::Hash256;

/// Timeout for establishing a HELLO handshake.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler {
    /// Currently loaded and initialised beacon chain.
    chain: Arc<BeaconChain>,
    /// The syncing framework.
    sync: SimpleSync,
    /// The network channel to relay messages to the Network service.
    network_send: crossbeam_channel::Sender<NetworkMessage>,
    /// A mapping of peers we have sent a HELLO rpc request to.
    hello_requests: HashMap<PeerId, Instant>,
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
        //TODO: Load genesis from BeaconChain
        //TODO: Initialise beacon chain
        let temp_genesis = Hash256::zero();

        // generate the Message handler
        let sync = SimpleSync::new(temp_genesis);
        let mut handler = MessageHandler {
            chain: beacon_chain.clone(),
            sync,
            network_send,
            hello_requests: HashMap::new(),
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
                // register RPC request
                self.hello_requests.insert(peer_id.clone(), Instant::now());
                self.send_hello(peer_id);
            }
            //TODO: Handle all messages
            _ => {}
        }
    }

    /// Sends a HELLO RPC request to a newly connected peer.
    fn send_hello(&self, peer_id: PeerId) {
        // send the hello request to the network
        //sync.hello()
    }
}
