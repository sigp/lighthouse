use libp2p::PeerId;
use libp2p::{HelloMessage, RpcEvent};
use types::{Hash256, Slot};

/// Messages between nodes across the network.
#[derive(Debug, Clone)]
pub enum NodeMessage {
    RPC(RpcEvent),
    BlockRequest,
    // TODO: only for testing - remove
    Message(String),
}

/// Types of messages that the network service can receive.
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    /// Send a message to libp2p service.
    //TODO: Define typing for messages across the wire
    Send(PeerId, NodeMessage),
}
