use crate::error;
use crate::messages::NodeMessage;
use beacon_chain::BeaconChain;
use crossbeam_channel::{unbounded as channel, Sender, TryRecvError};
use futures::future;
use futures::prelude::*;
use libp2p::rpc;
use libp2p::{PeerId, RPCEvent};
use slog::debug;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sync::SimpleSync;
use types::Hash256;

/// Timeout for establishing a HELLO handshake.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler<T: ClientTypes> {
    /// Currently loaded and initialised beacon chain.
    chain: BeaconChain<T::DB, T::SlotClock, T::ForkChoice>,
    /// The syncing framework.
    sync: SimpleSync,
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

impl<T: ClientTypes> MessageHandler<T> {
    /// Initializes and runs the MessageHandler.
    pub fn new(
        beacon_chain: Arc<BeaconChain<T::DB, T::SlotClock, T::ForkChoice>>,
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
            chain: beacon_chain,
            sync,
            hello_requests: HashMap::new(),
            log: log.clone(),
        };

        // spawn handler task
        // TODO: Handle manual termination of thread
        executor.spawn(future::poll_fn(move || -> Result<_, _> {
            loop {
                handler.handle_message(handler_recv.recv().map_err(|_| {
                    debug!(log, "Handler channel closed. Handler terminating");
                })?);
            }
        }));

        Ok(handler_send)
    }

    fn handle_message(&mut self, message: HandlerMessage) {
        match message {
            HandlerMessage::PeerDialed(peer_id) => self.send_hello(peer_id),
            //TODO: Handle all messages
            _ => {}
        }
    }

    /// Sends a HELLO RPC request to a newly connected peer.
    fn send_hello(&self, peer_id: PeerId) {}
}
