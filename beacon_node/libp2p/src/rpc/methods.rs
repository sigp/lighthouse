/// Available RPC methods types and ids.
use ssz_derive::{Decode, Encode};
use types::{Epoch, Hash256, Slot};

#[derive(Debug)]
pub enum RPCMethod {
    Hello,
    Goodbye,
    BeaconBlockRoots,
    Unknown,
}

impl From<u16> for RPCMethod {
    fn from(method_id: u16) -> Self {
        match method_id {
            0 => RPCMethod::Hello,
            1 => RPCMethod::Goodbye,
            10 => RPCMethod::BeaconBlockRoots,
            _ => RPCMethod::Unknown,
        }
    }
}

impl Into<u16> for RPCMethod {
    fn into(self) -> u16 {
        match self {
            RPCMethod::Hello => 0,
            RPCMethod::Goodbye => 1,
            RPCMethod::BeaconBlockRoots => 10,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RPCRequest {
    Hello(HelloMessage),
    Goodbye(u64),
    BeaconBlockRoots(BeaconBlockRootsRequest),
}

#[derive(Debug, Clone)]
pub enum RPCResponse {
    Hello(HelloMessage),
    BeaconBlockRoots(BeaconBlockRootsResponse),
}

/* Request/Response data structures for RPC methods */

/// The HELLO request/response handshake message.
#[derive(Encode, Decode, Clone, Debug)]
pub struct HelloMessage {
    /// The network ID of the peer.
    pub network_id: u8,
    /// The peers last finalized root.
    pub latest_finalized_root: Hash256,
    /// The peers last finalized epoch.
    pub latest_finalized_epoch: Epoch,
    /// The peers last block root.
    pub best_root: Hash256,
    /// The peers last slot.
    pub best_slot: Slot,
}

/// Request a number of beacon block roots from a peer.
#[derive(Encode, Decode, Clone, Debug)]
pub struct BeaconBlockRootsRequest {
    /// The starting slot of the requested blocks.
    start_slot: Slot,
    /// The number of blocks from the start slot.
    count: u64, // this must be less than 32768. //TODO: Enforce this in the lower layers
}

/// Response a number of beacon block roots from a peer.
#[derive(Encode, Decode, Clone, Debug)]
pub struct BeaconBlockRootsResponse {
    /// List of requested blocks and associated slots.
    roots: Vec<BlockRootSlot>,
}

/// Contains a block root and associated slot.
#[derive(Encode, Decode, Clone, Debug)]
pub struct BlockRootSlot {
    /// The block root.
    block_root: Hash256,
    /// The block slot.
    slot: Slot,
}
