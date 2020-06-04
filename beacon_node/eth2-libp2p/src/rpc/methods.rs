//! Available RPC methods types and ids.

use crate::types::EnrBitfield;
use serde::Serialize;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U1024, U256},
    VariableList,
};
use types::{Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// Maximum number of blocks in a single request.
#[allow(non_camel_case_types)]
type MAX_REQUEST_BLOCKS = U1024;

/// Maximum length of error message.
#[allow(non_camel_case_types)]
type MAX_ERROR_LEN = U256;

#[derive(Debug, Clone)]
pub struct ErrorType(VariableList<u8, MAX_ERROR_LEN>);

impl From<String> for ErrorType {
    fn from(s: String) -> Self {
        Self(VariableList::from(s.as_bytes().to_vec()))
    }
}

impl From<&str> for ErrorType {
    fn from(s: &str) -> Self {
        Self(VariableList::from(s.as_bytes().to_vec()))
    }
}

impl std::ops::Deref for ErrorType {
    type Target = VariableList<u8, MAX_ERROR_LEN>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/* Request/Response data structures for RPC methods */

/* Requests */

/// Identifier of a request.
///
// NOTE: The handler stores the `RequestId` to inform back of responses and errors, but it's execution
// is independent of the contents on this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestId {
    Router,
    Sync(usize),
    Behaviour,
}

/// The STATUS request/response handshake message.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct StatusMessage {
    /// The fork version of the chain we are broadcasting.
    pub fork_digest: [u8; 4],

    /// Latest finalized root.
    pub finalized_root: Hash256,

    /// Latest finalized epoch.
    pub finalized_epoch: Epoch,

    /// The latest block root.
    pub head_root: Hash256,

    /// The slot associated with the latest block root.
    pub head_slot: Slot,
}

/// The PING request/response message.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct Ping {
    /// The metadata sequence number.
    pub data: u64,
}

/// The METADATA response structure.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct MetaData<T: EthSpec> {
    /// A sequential counter indicating when data gets modified.
    pub seq_number: u64,
    /// The persistent subnet bitfield.
    pub attnets: EnrBitfield<T>,
}

/// The reason given for a `Goodbye` message.
///
/// Note: any unknown `u64::into(n)` will resolve to `Goodbye::Unknown` for any unknown `n`,
/// however `GoodbyeReason::Unknown.into()` will go into `0_u64`. Therefore de-serializing then
/// re-serializing may not return the same bytes.
#[derive(Debug, Clone, PartialEq)]
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

impl ssz::Encode for GoodbyeReason {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        0_u64.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let conv: u64 = self.clone().into();
        conv.ssz_append(buf)
    }
}

impl ssz::Decode for GoodbyeReason {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        u64::from_ssz_bytes(bytes).and_then(|n| Ok(n.into()))
    }
}

/// Request a number of beacon block roots from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BlocksByRangeRequest {
    /// The starting slot to request blocks.
    pub start_slot: u64,

    /// The number of blocks from the start slot.
    pub count: u64,

    /// The step increment to receive blocks.
    ///
    /// A value of 1 returns every block.
    /// A value of 2 returns every second block.
    /// A value of 3 returns every third block and so on.
    pub step: u64,
}

/// Request a number of beacon block bodies from a peer.
#[derive(Clone, Debug, PartialEq)]
pub struct BlocksByRootRequest {
    /// The list of beacon block bodies being requested.
    pub block_roots: VariableList<Hash256, MAX_REQUEST_BLOCKS>,
}

/* RPC Handling and Grouping */
// Collection of enums and structs used by the Codecs to encode/decode RPC messages

#[derive(Debug, Clone, PartialEq)]
pub enum RPCResponse<T: EthSpec> {
    /// A HELLO message.
    Status(StatusMessage),

    /// A response to a get BLOCKS_BY_RANGE request. A None response signifies the end of the
    /// batch.
    BlocksByRange(Box<SignedBeaconBlock<T>>),

    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Box<SignedBeaconBlock<T>>),

    /// A PONG response to a PING request.
    Pong(Ping),

    /// A response to a META_DATA request.
    MetaData(MetaData<T>),
}

/// Indicates which response is being terminated by a stream termination response.
#[derive(Debug, Clone)]
pub enum ResponseTermination {
    /// Blocks by range stream termination.
    BlocksByRange,

    /// Blocks by root stream termination.
    BlocksByRoot,
}

/// The structured response containing a result/code indicating success or failure
/// and the contents of the response
#[derive(Debug, Clone)]
pub enum RPCCodedResponse<T: EthSpec> {
    /// The response is a successful.
    Success(RPCResponse<T>),

    /// The response was invalid.
    InvalidRequest(ErrorType),

    /// The response indicates a server error.
    ServerError(ErrorType),

    /// There was an unknown response.
    // TODO: spec doesn't specify that this needs to be an ssz list
    // keeping this for consistency.
    Unknown(ErrorType),

    /// Received a stream termination indicating which response is being terminated.
    StreamTermination(ResponseTermination),
}

/// The code assigned to an erroneous `RPCResponse`.
#[derive(Debug, Clone, Copy)]
pub enum RPCResponseErrorCode {
    InvalidRequest,
    ServerError,
    Unknown,
}

impl<T: EthSpec> RPCCodedResponse<T> {
    /// Used to encode the response in the codec.
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            RPCCodedResponse::Success(_) => Some(0),
            RPCCodedResponse::InvalidRequest(_) => Some(1),
            RPCCodedResponse::ServerError(_) => Some(2),
            RPCCodedResponse::Unknown(_) => Some(255),
            RPCCodedResponse::StreamTermination(_) => None,
        }
    }

    /// Tells the codec whether to decode as an RPCResponse or an error.
    pub fn is_response(response_code: u8) -> bool {
        match response_code {
            0 => true,
            _ => false,
        }
    }

    /// Builds an RPCCodedResponse from a response code and an ErrorMessage
    pub fn from_error(response_code: u8, err: String) -> Self {
        match response_code {
            1 => RPCCodedResponse::InvalidRequest(err.into()),
            2 => RPCCodedResponse::ServerError(err.into()),
            _ => RPCCodedResponse::Unknown(err.into()),
        }
    }

    /// Builds an RPCCodedResponse from a response code and an ErrorMessage
    pub fn from_error_code(response_code: RPCResponseErrorCode, err: String) -> Self {
        match response_code {
            RPCResponseErrorCode::InvalidRequest => RPCCodedResponse::InvalidRequest(err),
            RPCResponseErrorCode::ServerError => RPCCodedResponse::ServerError(err),
            RPCResponseErrorCode::Unknown => RPCCodedResponse::Unknown(err),
        }
    }

    /// Specifies which response allows for multiple chunks for the stream handler.
    pub fn multiple_responses(&self) -> bool {
        match self {
            RPCCodedResponse::Success(resp) => match resp {
                RPCResponse::Status(_) => false,
                RPCResponse::BlocksByRange(_) => true,
                RPCResponse::BlocksByRoot(_) => true,
                RPCResponse::Pong(_) => false,
                RPCResponse::MetaData(_) => false,
            },
            RPCCodedResponse::InvalidRequest(_) => true,
            RPCCodedResponse::ServerError(_) => true,
            RPCCodedResponse::Unknown(_) => true,
            // Stream terminations are part of responses that have chunks
            RPCCodedResponse::StreamTermination(_) => true,
        }
    }

    /// Returns true if this response is an error. Used to terminate the stream after an error is
    /// sent.
    pub fn is_error(&self) -> bool {
        match self {
            RPCCodedResponse::Success(_) => false,
            _ => true,
        }
    }

    pub fn error_code(&self) -> Option<RPCResponseErrorCode> {
        match self {
            RPCCodedResponse::Success(_) => None,
            RPCCodedResponse::StreamTermination(_) => None,
            RPCCodedResponse::InvalidRequest(_) => Some(RPCResponseErrorCode::InvalidRequest),
            RPCCodedResponse::ServerError(_) => Some(RPCResponseErrorCode::ServerError),
            RPCCodedResponse::Unknown(_) => Some(RPCResponseErrorCode::Unknown),
        }
    }
}

impl std::fmt::Display for RPCResponseErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            RPCResponseErrorCode::InvalidRequest => "The request was invalid",
            RPCResponseErrorCode::ServerError => "Server error occurred",
            RPCResponseErrorCode::Unknown => "Unknown error occurred",
        };
        f.write_str(repr)
    }
}

impl std::fmt::Display for StatusMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status Message: Fork Digest: {:?}, Finalized Root: {}, Finalized Epoch: {}, Head Root: {}, Head Slot: {}", self.fork_digest, self.finalized_root, self.finalized_epoch, self.head_root, self.head_slot)
    }
}

impl<T: EthSpec> std::fmt::Display for RPCResponse<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCResponse::Status(status) => write!(f, "{}", status),
            RPCResponse::BlocksByRange(block) => {
                write!(f, "BlocksByRange: Block slot: {}", block.message.slot)
            }
            RPCResponse::BlocksByRoot(block) => {
                write!(f, "BlocksByRoot: BLock slot: {}", block.message.slot)
            }
            RPCResponse::Pong(ping) => write!(f, "Pong: {}", ping.data),
            RPCResponse::MetaData(metadata) => write!(f, "Metadata: {}", metadata.seq_number),
        }
    }
}

impl<T: EthSpec> std::fmt::Display for RPCCodedResponse<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCCodedResponse::Success(res) => write!(f, "{}", res),
            RPCCodedResponse::InvalidRequest(err) => write!(f, "Invalid Request: {:?}", err),
            RPCCodedResponse::ServerError(err) => write!(f, "Server Error: {:?}", err),
            RPCCodedResponse::Unknown(err) => write!(f, "Unknown Error: {:?}", err),
            RPCCodedResponse::StreamTermination(_) => write!(f, "Stream Termination"),
        }
    }
}

impl std::fmt::Display for GoodbyeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoodbyeReason::ClientShutdown => write!(f, "Client Shutdown"),
            GoodbyeReason::IrrelevantNetwork => write!(f, "Irrelevant Network"),
            GoodbyeReason::Fault => write!(f, "Fault"),
            GoodbyeReason::Unknown => write!(f, "Unknown Reason"),
        }
    }
}

impl std::fmt::Display for BlocksByRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start Slot: {}, Count: {}, Step: {}",
            self.start_slot, self.count, self.step
        )
    }
}

impl slog::Value for RequestId {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        match self {
            RequestId::Behaviour => slog::Value::serialize("Behaviour", record, key, serializer),
            RequestId::Router => slog::Value::serialize("Router", record, key, serializer),
            RequestId::Sync(ref id) => slog::Value::serialize(id, record, key, serializer),
        }
    }
}
