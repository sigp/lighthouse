//!Available RPC methods types and ids.

use ssz::{impl_decode_via_from, impl_encode_via_from};
use ssz_derive::{Decode, Encode};
use types::{Epoch, Hash256, Slot};

/* Request/Response data structures for RPC methods */

/* Requests */

/// The HELLO request/response handshake message.
#[derive(Encode, Decode, Clone, Debug)]
pub struct HelloMessage {
    /// The network ID of the peer.
    pub network_id: u8,

    /// The chain id for the HELLO request.
    pub chain_id: u64,

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
/// Note: any unknown `u64::into(n)` will resolve to `Goodbye::Unknown` for any unknown `n`,
/// however `Goodbye::Unknown.into()` will go into `0_u64`. Therefore de-serializing then
/// re-serializing may not return the same bytes.
#[derive(Debug, Clone)]
pub enum Goodbye {
    /// This node has shutdown.
    ClientShutdown = 1,

    /// Incompatible networks.
    IrreleventNetwork = 2,

    /// Error/fault in the RPC.
    Fault = 3,

    /// Unknown reason.
    Unknown = 0,
}

impl From<u64> for Goodbye {
    fn from(id: u64) -> Goodbye {
        match id {
            1 => Goodbye::ClientShutdown,
            2 => Goodbye::IrreleventNetwork,
            3 => Goodbye::Fault,
            _ => Goodbye::Unknown,
        }
    }
}

impl Into<u64> for Goodbye {
    fn into(self) -> u64 {
        self as u64
    }
}

impl_encode_via_from!(Goodbye, u64);
impl_decode_via_from!(Goodbye, u64);

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

/// Contains a block root and associated slot.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BlockRootSlot {
    /// The block root.
    pub block_root: Hash256,

    /// The block slot.
    pub slot: Slot,
}

/// The response of a beacon block roots request.
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
#[derive(Clone, Debug, PartialEq)]
pub struct BeaconBlockHeadersResponse {
    /// The list of ssz-encoded requested beacon block headers.
    pub headers: Vec<u8>,
}

/// Request a number of beacon block bodies from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BeaconBlockBodiesRequest {
    /// The list of beacon block bodies being requested.
    pub block_roots: Vec<Hash256>,
}

/// Response containing the list of requested beacon block bodies.
#[derive(Clone, Debug, PartialEq)]
pub struct BeaconBlockBodiesResponse {
    /// The list of ssz-encoded beacon block bodies being requested.
    pub block_bodies: Vec<u8>,
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
    pub values: bool, //TBD - stubbed with encodable bool
}
