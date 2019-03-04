use crate::error;
use crate::messages::NodeMessage;
use crossbeam_channel::{unbounded as channel, Sender};
use libp2p::PeerId;
use slog::debug;
use sync::SimpleSync;
use types::Hash256;

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler {
    sync: SimpleSync,
    //TODO: Implement beacon chain
    //chain: BeaconChain
}

/// Types of messages the handler can receive.
pub enum HandlerMessage {
    /// Peer has connected.
    PeerConnected(PeerId),
    /// Peer has disconnected,
    PeerDisconnected(PeerId),
    /// A Node message has been received.
    Message(PeerId, NodeMessage),
}

impl MessageHandler {
    /// Initializes and runs the MessageHandler.
    pub fn new(log: slog::Logger) -> error::Result<Sender<HandlerMessage>> {
        debug!(log, "Service starting");

        let (handler_send, handler_recv) = channel();

        // Initialise sync and begin processing in thread
        //TODO: Load genesis from BeaconChain
        let temp_genesis = Hash256::zero();
        let sync = SimpleSync::new(temp_genesis);

        let handler = MessageHandler { sync };

        // spawn handler thread

        Ok(handler_send)
    }
}
