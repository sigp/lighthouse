use libp2p::PeerId;
use types::{Hash256, Slot};

/// Messages between nodes across the network.
#[derive(Debug, Clone)]
pub enum NodeMessage {
    Status(Status),
    BlockRequest,
    // TODO: only for testing - remove
    Message(String),
}

#[derive(Debug, Clone)]
pub struct Status {
    /// Current node version.
    version: u8,
    /// Genesis Hash.
    genesis_hash: Hash256,
    /// Best known slot number.
    best_slot: Slot,
    /// Best known slot hash.
    best_slot_hash: Hash256,
}

/// Types of messages that the network service can receive.
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    /// Send a message to libp2p service.
    //TODO: Define typing for messages across the wire
    Send(PeerId, NodeMessage),
}
