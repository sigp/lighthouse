//!Available RPC methods types and ids.

use ssz::{impl_decode_via_from, impl_encode_via_from};
use ssz_derive::{Decode, Encode};
use types::{BeaconBlockBody, Epoch, EthSpec, Hash256, Slot};

/* Request/Response data structures for RPC methods */

/* Requests */

pub type RequestId = usize;

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
/// however `GoodbyeReason::Unknown.into()` will go into `0_u64`. Therefore de-serializing then
/// re-serializing may not return the same bytes.
#[derive(Debug, Clone)]
pub enum GoodbyeReason {
    /// This node has shutdown.
    ClientShutdown = 1,

    /// Incompatible networks.
    IrrelevantNetwork = 2,

    /// Error/fault in the RPC.
    Fault = 3,

    /// Unknown reason.
    Unknown = 0,
}

impl From<u64> for GoodbyeReason {
    fn from(id: u64) -> GoodbyeReason {
        match id {
            1 => GoodbyeReason::ClientShutdown,
            2 => GoodbyeReason::IrrelevantNetwork,
            3 => GoodbyeReason::Fault,
            _ => GoodbyeReason::Unknown,
        }
    }
}

impl Into<u64> for GoodbyeReason {
    fn into(self) -> u64 {
        self as u64
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
    /// The list of hashes that were sent in the request and match these roots response. None when
    /// sending outbound.
    pub block_roots: Option<Vec<Hash256>>,
    /// The list of ssz-encoded beacon block bodies being requested.
    pub block_bodies: Vec<u8>,
}

/// The decoded version of `BeaconBlockBodiesResponse` which is expected in `SimpleSync`.
pub struct DecodedBeaconBlockBodiesResponse<E: EthSpec> {
    /// The list of hashes sent in the request to get this response.
    pub block_roots: Vec<Hash256>,
    /// The valid decoded block bodies.
    pub block_bodies: Vec<BeaconBlockBody<E>>,
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

/* RPC Handling and Grouping */
// Collection of enums and structs used by the Codecs to encode/decode RPC messages

#[derive(Debug, Clone)]
pub enum RPCResponse {
    /// A HELLO message.
    Hello(HelloMessage),
    /// A response to a get BEACON_BLOCK_ROOTS request.
    BeaconBlockRoots(BeaconBlockRootsResponse),
    /// A response to a get BEACON_BLOCK_HEADERS request.
    BeaconBlockHeaders(BeaconBlockHeadersResponse),
    /// A response to a get BEACON_BLOCK_BODIES request.
    BeaconBlockBodies(BeaconBlockBodiesResponse),
    /// A response to a get BEACON_CHAIN_STATE request.
    BeaconChainState(BeaconChainStateResponse),
}

#[derive(Debug)]
pub enum RPCErrorResponse {
    Success(RPCResponse),
    InvalidRequest(ErrorMessage),
    ServerError(ErrorMessage),
    Unknown(ErrorMessage),
}

impl RPCErrorResponse {
    /// Used to encode the response.
    pub fn as_u8(&self) -> u8 {
        match self {
            RPCErrorResponse::Success(_) => 0,
            RPCErrorResponse::InvalidRequest(_) => 2,
            RPCErrorResponse::ServerError(_) => 3,
            RPCErrorResponse::Unknown(_) => 255,
        }
    }

    /// Tells the codec whether to decode as an RPCResponse or an error.
    pub fn is_response(response_code: u8) -> bool {
        match response_code {
            0 => true,
            _ => false,
        }
    }

    /// Builds an RPCErrorResponse from a response code and an ErrorMessage
    pub fn from_error(response_code: u8, err: ErrorMessage) -> Self {
        match response_code {
            2 => RPCErrorResponse::InvalidRequest(err),
            3 => RPCErrorResponse::ServerError(err),
            _ => RPCErrorResponse::Unknown(err),
        }
    }
}

#[derive(Encode, Decode, Debug)]
pub struct ErrorMessage {
    /// The UTF-8 encoded Error message string.
    pub error_message: Vec<u8>,
}

impl ErrorMessage {
    pub fn as_string(&self) -> String {
        String::from_utf8(self.error_message.clone()).unwrap_or_else(|_| "".into())
    }
}
