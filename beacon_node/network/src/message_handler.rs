use crate::error;
use crate::messages::NodeMessage;
use crossbeam_channel::{unbounded as channel, Sender, TryRecvError};
use futures::future;
use futures::prelude::*;
use libp2p::rpc;
use libp2p::{PeerId, RpcEvent};
use slog::debug;
use sync::SimpleSync;
use types::Hash256;

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler {
    sync: SimpleSync,
    //TODO: Implement beacon chain
    //chain: BeaconChain
    log: slog::Logger,
}

/// Types of messages the handler can receive.
#[derive(Debug, Clone)]
pub enum HandlerMessage {
    /// Peer has connected.
    PeerConnected(PeerId),
    /// Peer has disconnected,
    PeerDisconnected(PeerId),
    /// A Node message has been received.
    Message(PeerId, NodeMessage),
    /// An RPC response/request has been received.
    RPC(RpcEvent),
}

impl MessageHandler {
    /// Initializes and runs the MessageHandler.
    pub fn new(
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<Sender<HandlerMessage>> {
        debug!(log, "Service starting");

        let (handler_send, handler_recv) = channel();

        // Initialise sync and begin processing in thread
        //TODO: Load genesis from BeaconChain
        let temp_genesis = Hash256::zero();

        // generate the Message handler
        let sync = SimpleSync::new(temp_genesis);
        //TODO: Initialise beacon chain
        let mut handler = MessageHandler {
            sync,
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
        debug!(self.log, "Message received {:?}", message);
    }
}
