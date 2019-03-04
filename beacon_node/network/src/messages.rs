use types::{H256,Slot}

/// Messages between nodes across the network.
pub enum NodeMessage {

    Status(Status),
    BlockRequest,
}

pub struct Status {
        /// Current node version.
        version: u8
        /// Genesis Hash.
        genesis_hash: H256
        /// Best known slot number.
        best_slot: Slot
        /// Best known slot hash.
        best_slot_hash: H256
}

/// Types of messages that the network service can receive.
pub enum NetworkMessage {
    /// Send a message to libp2p service.
    //TODO: Define typing for messages accross the wire
    Send(Node, Message),
}

