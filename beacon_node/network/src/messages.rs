use libp2p::PeerId;
use libp2p::{HelloMessage, RPCEvent};
use types::{Hash256, Slot};

//TODO: This module can be entirely replaced in the RPC rewrite

/// Messages between nodes across the network.
//TODO: Remove this in the RPC rewrite
#[derive(Debug, Clone)]
pub enum NodeMessage {
    RPC(RPCEvent),
    BlockRequest,
    // TODO: only for testing - remove
    Message(String),
}
