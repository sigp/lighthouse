use super::methods::*;
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use ssz::{Decode, Encode};
use std::hash::Hasher;
use std::io;
use std::iter;
use tokio::io::{AsyncRead, AsyncWrite};

/// The maximum bytes that can be sent across the RPC.
const MAX_RPC_SIZE: usize = 4_194_304; // 4M
/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth/serenity/rpc/";

/// Implementation of the `ConnectionUpgrade` for the rpc protocol.
#[derive(Debug, Clone)]
pub struct RPCProtocol;

impl UpgradeInfo for RPCProtocol {
    type Info = &'static [u8];
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![
            b"/eth/serenity/rpc/hello/1/ssz",
            b"/eth/serenity/rpc/goodbye/1/ssz",
            b"/eth/serenity/rpc/beacon_block_roots/1/ssz",
            b"/eth/serenity/rpc/beacon_block_headers/1/ssz",
            b"/eth/serenity/rpc/beacon_block_bodies/1/ssz",
            b"/eth/serenity/rpc/beacon_chain_state/1/ssz",
        ]
    }
}

/// The outbound RPC type as well as the return type used in the behaviour.
#[derive(Debug, Clone)]
pub enum RPCEvent {
    Request(RPCRequest),
    Response(RPCResponse),
}

/* Inbound upgrade */

// The inbound protocol reads the request, decodes it and returns the stream to the protocol
// handler to respond to once ready.

type FnDecodeRPCEvent<TSocket> = fn(
    upgrade::Negotiated<TSocket>,
    Vec<u8>,
    (),
) -> Result<(upgrade::Negotiated<TSocket>, RPCEvent), RPCError>;

impl<TSocket> InboundUpgrade<TSocket> for RPCProtocol
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = (upgrade::Negotiated<TSocket>, RPCEvent);
    type Error = RPCError;
    type Future = upgrade::ReadRespond<upgrade::Negotiated<TSocket>, (), FnDecodeRPCEvent<TSocket>>;

    fn upgrade_inbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: Self::Info,
    ) -> Self::Future {
        upgrade::read_respond(socket, MAX_RPC_SIZE, (), |socket, packet, ()| {
            Ok((socket, decode_request(packet, protocol)?))
        })
    }
}

/* Outbound request */

// Combines all the RPC requests into a single enum to implement `UpgradeInfo` and
// `OutboundUpgrade`

/// The raw protocol id sent over the wire.
type RawProtocolId = Vec<u8>;

/// Tracks the types in a protocol id.
pub struct ProtocolId {
    /// The rpc message type/name.
    pub message_name: String,

    /// The version of the RPC.
    pub version: usize,

    /// The encoding of the RPC.
    pub encoding: String,
}

/// An RPC protocol ID.
impl ProtocolId {
    pub fn new(message_name: String, version: usize, encoding: String) -> Self {
        ProtocolId {
            message_name,
            version,
            encoding,
        }
    }

    /// Converts a raw RPC protocol id string into an `RPCProtocolId`
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, RPCError> {
        let protocol_string = String::from_utf8(bytes.as_vec())
            .map_err(|_| RPCError::InvalidProtocol("Invalid protocol Id"))?;
        let protocol_string = protocol_string.as_str().split('/');

        Ok(ProtocolId {
            message_name: protocol_string[3],
            version: protocol_string[4],
            encoding: protocol_string[5],
        })
    }
}

impl Into<RawProtocolId> for ProtocolId {
    fn into(&self) -> [u8] {
        &format!(
            "{}/{}/{}/{}",
            PROTOCOL_PREFIX, self.message_name, self.version, self.encoding
        )
        .as_bytes()
    }
}

#[derive(Debug, Clone)]
pub enum RPCRequest {
    Hello(HelloMessage),
    Goodbye(Goodbye),
    BeaconBlockRoots(BeaconBlockRootsRequest),
    BeaconBlockHeaders(BeaconBlockHeadersRequest),
    BeaconBlockBodies(BeaconBlockBodiesRequest),
    BeaconChainState(BeaconChainStateRequest),
}

impl UpgradeInfo for RPCRequest {
    type Info = RawProtocolId;
    type InfoIter = Vec<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        self.supported_protocols()
    }
}

//  GOODBYE RPC has it's own upgrade as it doesn't expect a response
impl UpgradeInfo for Goodbye {
    type Info = RawProtocolId;
    type InfoIter = iter::Once<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(ProtocolId::new("goodbye", 1, "ssz").into())
    }
}

/// Implements the encoding per supported protocol for RPCRequest.
impl RPCRequest {
    pub fn supported_protocols(&self) -> Vec<RawProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            RPCRequest::Hello(_) => vec![ProtocolId::new("hello", 1, "ssz").into()],
            RPCRequest::Goodbye(_) => vec![ProtocolId::new("goodbye", 1, "ssz").into()],
            RPCRequest::BeaconBlockRoots(_) => {
                vec![ProtocolId::new("beacon_block_roots", 1, "ssz").into()]
            }
            RPCRequest::BeaconBlockHeaders(_) => {
                vec![ProtocolId::new("beacon_block_headers", 1, "ssz").into()]
            }
            RPCRequest::BeaconBlockBodies(_) => {
                vec![ProtocolId::new("beacon_block_bodies", 1, "ssz").into()]
            }
            RPCRequest::BeaconBlockState(_) => {
                vec![ProtocolId::new("beacon_block_state", 1, "ssz").into()]
            }
        }
    }

    /// Encodes the Request object based on the negotiated protocol.
    pub fn encode(&self, protocol: RawProtocolId) -> Result<Vec<u8>, io::Error> {
        // Assume select has given a supported protocol.
        let protocol = ProtocolId::from_bytes(protocol)?;
        // Match on the encoding and in the future, the version
        match protocol.encoding {
            "ssz" => Ok(self.ssz_encode()),
            _ => {
                return Err(RPCError::Custom(format!(
                    "Unknown Encoding: {}",
                    protocol.encoding
                )))
            }
        }
    }

    fn ssz_encode(&self) {
        match self {
            RPCRequest::Hello(req) => req.as_ssz_bytes(),
            RPCRequest::Goodbye(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconBlockRoots(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconBlockHeaders(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconBlockBodies(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconChainState(req) => req.as_ssz_bytes(),
        }
    }
}

/* Outbound upgrades */

impl<TSocket> OutboundUpgrade<TSocket> for RPCRequest
where
    TSocket: AsyncWrite,
{
    type Output = ();
    type Error = io::Error;
    type Future = upgrade::WriteOne<upgrade::Negotiated<TSocket>>;

    fn upgrade_outbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: Self::Info,
    ) -> Self::Future {
        let bytes = self.encode(protocol);
        upgrade::request_response(socket, bytes, MAX_RPC_SIZE, protocol, |packet, protocol| {
            Ok(decode_response(packet, protocol)?)
        })
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for Goodbye
where
    TSocket: AsyncWrite,
{
    type Output = ();
    type Error = io::Error;
    type Future = upgrade::WriteOne<upgrade::Negotiated<TSocket>>;

    fn upgrade_outbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: Self::Info,
    ) -> Self::Future {
        let bytes = self.as_ssz_bytes();
        upgrade::write_one(socket, bytes)
    }
}

/* Decoding for Requests/Responses */

// This function can be extended to provide further logic for supporting various protocol versions/encoding
fn decode_request(packet: Vec<u8>, protocol: ProtocolId) -> Result<RPCRequest, io::Error> {
    let protocol_id = ProtocolId::from_bytes(protocol);

    match protocol_id.message_name {
        "hello" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCRequest::Hello(HelloMessage::from_ssz_bytes(&packet)?)),
                _ => Err(RPCError::InvalidProtocol("Unknown HELLO encoding")),
            },
            _ => Err(RPCError::InvalidProtocol("Unknown HELLO version")),
        },
        "goodbye" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCRequest::Goodbye(Goodbye::from_ssz_bytes(&packet)?)),
                _ => Err(RPCError::InvalidProtocol("Unknown GOODBYE encoding")),
            },
            _ => Err(RPCError::InvalidProtocol("Unknown GOODBYE version")),
        },
        "beacon_block_roots" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCRequest::BeaconBlockRooots(
                    BeaconBlockRootsRequest::from_ssz_bytes(&packet)?,
                )),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_BLOCK_ROOTS encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_BLOCK_ROOTS version",
            )),
        },
        "beacon_block_headers" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCRequest::BeaconBlockHeaders(
                    BeaconBlockHeadersRequest::from_ssz_bytes(&packet),
                )),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_BLOCK_HEADERS encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_BLOCK_HEADERS version",
            )),
        },
        "beacon_block_bodies" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCRequest::BeaconBlockBodies(
                    BeaconBlockBodiesRequest::from_ssz_bytes(&packet)?,
                )),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_BLOCK_BODIES encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_BLOCK_BODIES version",
            )),
        },
        "beacon_chain_state" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCRequest::BeaconChainState(
                    BeaconChainStateRequest::from_ssz_bytes(&packet)?,
                )),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_CHAIN_STATE encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_CHAIN_STATE version",
            )),
        },
    }
}

/// Decodes a response that was received on the same stream as a request. The response type should
/// therefore match the request protocol type.
fn decode_response(packet: Vec<u8>, protocol: RawProtocolId) -> Result<RPCResponse, RPCError> {
    let protocol_id = ProtocolId::from_bytes(protocol)?;

    match protocol_id.message_name {
        "hello" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCResponse::Hello(HelloMessage::from_ssz_bytes(&packet)?)),
                _ => Err(RPCError::InvalidProtocol("Unknown HELLO encoding")),
            },
            _ => Err(RPCError::InvalidProtocol("Unknown HELLO version")),
        },
        "goodbye" => Err(RPCError::Custom("GOODBYE should not have a response")),
        "beacon_block_roots" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCResponse::BeaconBlockRoots(
                    BeaconBlockRootsResponse::from_ssz_bytes(&packet)?,
                )),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_BLOCK_ROOTS encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_BLOCK_ROOTS version",
            )),
        },
        "beacon_block_headers" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCResponse::BeaconBlockHeaders(
                    BeaconBlockHeadersResponse { headers: packet },
                )),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_BLOCK_HEADERS encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_BLOCK_HEADERS version",
            )),
        },
        "beacon_block_bodies" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(RPCResponse::BeaconBlockBodies(BeaconBlockBodiesResponse {
                    block_bodies: packet,
                })),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_BLOCK_BODIES encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_BLOCK_BODIES version",
            )),
        },
        "beacon_chain_state" => match protocol_id.version {
            "1" => match protocol_id.encoding {
                "ssz" => Ok(BeaconChainStateRequest::from_ssz_bytes(&packet)?),
                _ => Err(RPCError::InvalidProtocol(
                    "Unknown BEACON_CHAIN_STATE encoding",
                )),
            },
            _ => Err(RPCError::InvalidProtocol(
                "Unknown BEACON_CHAIN_STATE version",
            )),
        },
    }
}

/// Error in RPC Encoding/Decoding.
#[derive(Debug)]
pub enum RPCError {
    /// Error when reading the packet from the socket.
    ReadError(upgrade::ReadOneError),
    /// Error when decoding the raw buffer from ssz.
    SSZDecodeError(ssz::DecodeError),
    /// Invalid Protocol ID
    InvalidProtocol(&'static str),
    /// Custom message.
    Custom(String),
}

impl From<upgrade::ReadOneError> for RPCError {
    #[inline]
    fn from(err: upgrade::ReadOneError) -> Self {
        RPCError::ReadError(err)
    }
}

impl From<ssz::DecodeError> for RPCError {
    #[inline]
    fn from(err: ssz::DecodeError) -> Self {
        RPCError::SSZDecodeError(err)
    }
}
