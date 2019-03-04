use crate::node_message::NodeMessage;

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler {
    sync: Syncer,
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
    Message(Peer, NodeMessage),
}
