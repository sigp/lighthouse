//!Available RPC methods types and ids.

use ssz::{impl_decode_via_from, impl_encode_via_from};
use ssz_derive::{Decode, Encode};
use types::{BeaconBlockBody, BeaconBlockHeader, Epoch, Hash256, Slot};

#[derive(Debug)]
/// Available Serenity Libp2p RPC methods
pub enum RPCMethod {
    /// Initialise handshake between connecting peers.
    Hello,
    /// Terminate a connection providing a reason.
    Goodbye,
    /// Requests a number of beacon block roots.
    BeaconBlockRoots,
    /// Requests a number of beacon block headers.
    BeaconBlockHeaders,
    /// Requests a number of beacon block bodies.
    BeaconBlockBodies,
    /// Requests values for a merkle proof for the current blocks state root.
    BeaconChainState, // Note: experimental, not complete.
    /// Unknown method received.
    Unknown,
}

pub enum RawRPCRequest


#[derive(Debug, Clone)]
pub enum RPCRequest {
    Hello(HelloMessage),
    Goodbye(GoodbyeReason),
    BeaconBlockRoots(BeaconBlockRootsRequest),
    BeaconBlockHeaders(BeaconBlockHeadersRequest),
    BeaconBlockBodies(BeaconBlockBodiesRequest),
    BeaconChainState(BeaconChainStateRequest),
}

#[derive(Debug, Clone)]
pub enum RPCResponse {
    Hello(HelloMessage),
    BeaconBlockRoots(BeaconBlockRootsResponse),
    BeaconBlockHeaders(BeaconBlockHeadersResponse),
    BeaconBlockBodies(BeaconBlockBodiesResponse),
    BeaconChainState(BeaconChainStateResponse),
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

/// The reason given for a `Goodbye` message.
///
/// Note: any unknown `u64::into(n)` will resolve to `GoodbyeReason::Unknown` for any unknown `n`,
/// however `GoodbyeReason::Unknown.into()` will go into `0_u64`. Therefore de-serializing then
/// re-serializing may not return the same bytes.
#[derive(Debug, Clone)]
pub enum GoodbyeReason {
    ClientShutdown,
    IrreleventNetwork,
    Fault,
    Unknown,
}

impl From<u64> for GoodbyeReason {
    fn from(id: u64) -> GoodbyeReason {
        match id {
            1 => GoodbyeReason::ClientShutdown,
            2 => GoodbyeReason::IrreleventNetwork,
            3 => GoodbyeReason::Fault,
            _ => GoodbyeReason::Unknown,
        }
    }
}

impl Into<u64> for GoodbyeReason {
    fn into(self) -> u64 {
        match self {
            GoodbyeReason::Unknown => 0,
            GoodbyeReason::ClientShutdown => 1,
            GoodbyeReason::IrreleventNetwork => 2,
            GoodbyeReason::Fault => 3,
        }
    }
}

impl_encode_via_from!(GoodbyeReason, u64);
impl_decode_via_from!(GoodbyeReason, u64);

/// Request a number of beacon block roots from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconBlockRootsRequest {
    /// The starting slot of the requested blocks.
    pub start_slot: Slot,
    /// The number of blocks from the start slot.
    pub count: u64, // this must be less than 32768. //TODO: Enforce this in the lower layers
}

/// Response containing a number of beacon block roots from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconBlockRootsResponse {
    /// List of requested blocks and associated slots.
    pub roots: Vec<BlockRootSlot>,
}

impl BeaconBlockRootsResponse {
    /// Returns `true` if each `self.roots.slot[i]` is higher than the preceding `i`.
    pub fn slots_are_ascending(&self) -> bool {
        for window in self.roots.windows(2) {
            if window[0].slot >= window[1].slot {
                return false;
            }
        }

        true
    }
}

/// Contains a block root and associated slot.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BlockRootSlot {
    /// The block root.
    pub block_root: Hash256,
    /// The block slot.
    pub slot: Slot,
}

/// Request a number of beacon block headers from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconBlockHeadersRequest {
    /// The starting header hash of the requested headers.
    pub start_root: Hash256,
    /// The starting slot of the requested headers.
    pub start_slot: Slot,
    /// The maximum number of headers than can be returned.
    pub max_headers: u64,
    /// The maximum number of slots to skip between blocks.
    pub skip_slots: u64,
}

/// Response containing requested block headers.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconBlockHeadersResponse {
    /// The list of requested beacon block headers.
    pub headers: Vec<BeaconBlockHeader>,
}

/// Request a number of beacon block bodies from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconBlockBodiesRequest {
    /// The list of beacon block bodies being requested.
    pub block_roots: Vec<Hash256>,
}

/// Response containing the list of requested beacon block bodies.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconBlockBodiesResponse {
    /// The list of beacon block bodies being requested.
    pub block_bodies: Vec<BeaconBlockBody>,
}

/// Request values for tree hashes which yield a blocks `state_root`.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconChainStateRequest {
    /// The tree hashes that a value is requested for.
    pub hashes: Vec<Hash256>,
}

/// Request values for tree hashes which yield a blocks `state_root`.
// Note: TBD
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconChainStateResponse {
    /// The values corresponding the to the requested tree hashes.
    pub values: bool, //TBD - stubbed with encodeable bool
}
