use super::methods::*;
use crate::rpc::codec::{
    base::{BaseInboundCodec, BaseOutboundCodec},
    ssz::{SSZInboundCodec, SSZOutboundCodec},
};
use futures::future::Future;
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::io;
use std::time::Duration;
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::prelude::future::MapErr;
use tokio::prelude::*;
use tokio::util::FutureExt;

/// The maximum bytes that can be sent across the RPC.
const MAX_RPC_SIZE: usize = 4_194_304; // 4M
/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth/serenity/rpc/";
/// The number of seconds to wait for a response before the stream is terminated.
const RESPONSE_TIMEOUT: u64 = 10;

/// Implementation of the `ConnectionUpgrade` for the RPC protocol.
#[derive(Debug, Clone)]
pub struct RPCProtocol;

impl UpgradeInfo for RPCProtocol {
    type Info = &'static [u8];
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![
            b"/eth/serenity/rpc/hello/1.0.0/ssz",
            b"/eth/serenity/rpc/goodbye/1.0.0/ssz",
            b"/eth/serenity/rpc/beacon_block_roots/1.0.0/ssz",
            b"/eth/serenity/rpc/beacon_block_headers/1.0.0/ssz",
            b"/eth/serenity/rpc/beacon_block_bodies/1.0.0/ssz",
            b"/eth/serenity/rpc/beacon_chain_state/1.0.0/ssz",
        ]
    }
}

/// The raw protocol id sent over the wire.
type RawProtocolId = Vec<u8>;

/// Tracks the types in a protocol id.
pub struct ProtocolId {
    /// The rpc message type/name.
    pub message_name: String,

    /// The version of the RPC.
    pub version: String,

    /// The encoding of the RPC.
    pub encoding: String,
}

/// An RPC protocol ID.
impl ProtocolId {
    pub fn new(message_name: &str, version: &str, encoding: &str) -> Self {
        ProtocolId {
            message_name: message_name.into(),
            version: version.into(),
            encoding: encoding.into(),
        }
    }

    /// Converts a raw RPC protocol id string into an `RPCProtocolId`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RPCError> {
        let protocol_string = String::from_utf8(bytes.to_vec())
            .map_err(|_| RPCError::InvalidProtocol("Invalid protocol Id"))?;
        let protocol_list: Vec<&str> = protocol_string.as_str().split('/').take(5).collect();

        if protocol_list.len() != 5 {
            return Err(RPCError::InvalidProtocol("Not enough '/'"));
        }

        Ok(ProtocolId {
            message_name: protocol_list[3].into(),
            version: protocol_list[4].into(),
            encoding: protocol_list[5].into(),
        })
    }
}

impl Into<RawProtocolId> for ProtocolId {
    fn into(self) -> RawProtocolId {
        format!(
            "{}/{}/{}/{}",
            PROTOCOL_PREFIX, self.message_name, self.version, self.encoding
        )
        .as_bytes()
        .to_vec()
    }
}

/* Inbound upgrade */

// The inbound protocol reads the request, decodes it and returns the stream to the protocol
// handler to respond to once ready.

enum InboundCodec {
    SSZ(BaseInboundCodec<SSZInboundCodec>),
}

type FnDecodeRPCEvent<TSocket> =
    fn(
        upgrade::Negotiated<TSocket>,
        Vec<u8>,
        &'static [u8], // protocol id
    ) -> Result<(upgrade::Negotiated<TSocket>, RPCRequest, ProtocolId), RPCError>;

impl<TSocket> InboundUpgrade<TSocket> for RPCProtocol
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = RPCRequest;
    type Error = RPCError;

    type Future = Box<dyn Future<Item = Self::Output, Error = Self::Error>>;
    /*
    type Future = MapErr<
        tokio_timer::Timeout<
            upgrade::ReadRespond<
                upgrade::Negotiated<TSocket>,
                Self::Info,
                FnDecodeRPCEvent<TSocket>,
            >,
        >,
        fn(tokio::timer::timeout::Error<RPCError>) -> RPCError,
    >;
    */

    fn upgrade_inbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: &'static [u8],
    ) -> Self::Future {
        let protocol_id = match ProtocolId::from_bytes(protocol) {
            Ok(v) => v,
            Err(e) => return Box::new(futures::future::err(e)),
        };

        match protocol_id.encoding.as_str() {
            "ssz" | _ => {
                let codec = BaseInboundCodec::new(SSZInboundCodec::new(protocol_id, 4096));
                Box::new(
                    Framed::new(socket, codec)
                        .into_future()
                        .timeout(Duration::from_secs(RESPONSE_TIMEOUT))
                        .map_err(RPCError::from)
                        .and_then(|(madouby, _)| match madouby {
                            Some(x) => futures::future::ok(x),
                            None => futures::future::err(RPCError::Custom("Go home".into())),
                        }),
                )
            }
        }

        /*
            upgrade::read_respond(socket, MAX_RPC_SIZE, protocol, {
                |socket, packet, protocol| {
                    let protocol_id = ProtocolId::from_bytes(protocol)?;
                    Ok((
                        socket,
                        RPCRequest::decode(packet, protocol_id)?,
                        protocol_id,
                    ))
                }
            }
                as FnDecodeRPCEvent<TSocket>)
        }
        */
    }
}

/* Outbound request */

// Combines all the RPC requests into a single enum to implement `UpgradeInfo` and
// `OutboundUpgrade`

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

/// Implements the encoding per supported protocol for RPCRequest.
impl RPCRequest {
    pub fn supported_protocols(&self) -> Vec<RawProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            RPCRequest::Hello(_) => vec![ProtocolId::new("hello", "1.0.0", "ssz").into()],
            RPCRequest::Goodbye(_) => vec![ProtocolId::new("goodbye", "1.0.0", "ssz").into()],
            RPCRequest::BeaconBlockRoots(_) => {
                vec![ProtocolId::new("beacon_block_roots", "1.0.0", "ssz").into()]
            }
            RPCRequest::BeaconBlockHeaders(_) => {
                vec![ProtocolId::new("beacon_block_headers", "1.0.0", "ssz").into()]
            }
            RPCRequest::BeaconBlockBodies(_) => {
                vec![ProtocolId::new("beacon_block_bodies", "1.0.0", "ssz").into()]
            }
            RPCRequest::BeaconChainState(_) => {
                vec![ProtocolId::new("beacon_block_state", "1.0.0", "ssz").into()]
            }
        }
    }

    /// Encodes the Request object based on the negotiated protocol.
    pub fn encode(&self, protocol: ProtocolId) -> Result<Vec<u8>, RPCError> {
        // Match on the encoding and in the future, the version
        match protocol.encoding.as_str() {
            "ssz" => Ok(self.ssz_encode()),
            _ => {
                return Err(RPCError::Custom(format!(
                    "Unknown Encoding: {}",
                    protocol.encoding
                )))
            }
        }
    }

    fn ssz_encode(&self) -> Vec<u8> {
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

/* RPC Response type - used for outbound upgrades */

/* Outbound upgrades */

impl<TSocket> OutboundUpgrade<TSocket> for RPCRequest
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = RPCResponse;
    type Error = RPCError;
    type Future = Box<dyn Future<Item = Self::Output, Error = Self::Error>>;
    fn upgrade_outbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: Self::Info,
    ) -> Self::Future {
        panic!()

        /*
        let protocol_id = match ProtocolId::from_bytes(&protocol) {
            Ok(v) => v,
            Err(e) => return futures::future::err(e),
        };

        // select which codec to use
        let inbound_stream = match protocol_id.encoding.as_str() {
            "ssz" => {
                let codec = BaseInboundCodec::new(SSZCodec::new());
                Framed::new(socket, codec).send(self)
            }
            _ => futures::future::err(RPCError::InvalidProtocol("Unsupported encoding")),
        };

        // do not wait for a timeout if we send a GOODBYE request
        match protocol_id.message_name.as_str() {
            // goodbye messages do not have a response
            "goodbye" => inbound_stream.and_then(|| {
                RPCErrorResponse::Unknown(ErrorMessage {
                    error_message: String::from("goodbye response").as_bytes(),
                })
            }),
            // get a response for all other requests
            _ => inbound_stream.and_then(|stream| {
                stream
                    .into_future()
                    .timeout(Duration::from_secs(RESPONSE_TIMEOUT))
                    .map(|resp, _| resp)
                    .map_err(RPCError::from)
            }),
        }
        */
    }
}

/// Error in RPC Encoding/Decoding.
#[derive(Debug)]
pub enum RPCError {
    /// Error when reading the packet from the socket.
    ReadError(upgrade::ReadOneError),
    /// Error when decoding the raw buffer from ssz.
    SSZDecodeError(ssz::DecodeError),
    /// Invalid Protocol ID.
    InvalidProtocol(&'static str),
    /// IO Error.
    IoError(io::Error),
    /// Waiting for a request/response timed out, or timer error'd.
    StreamTimeout,
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
impl<T> From<tokio::timer::timeout::Error<T>> for RPCError {
    fn from(err: tokio::timer::timeout::Error<T>) -> Self {
        if err.is_elapsed() {
            RPCError::StreamTimeout
        } else {
            RPCError::Custom("Stream timer failed".into())
        }
    }
}

impl From<io::Error> for RPCError {
    fn from(err: io::Error) -> Self {
        RPCError::IoError(err)
    }
}

// Error trait is required for `ProtocolsHandler`
impl std::fmt::Display for RPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RPCError::ReadError(ref err) => write!(f, "Error while reading from socket: {}", err),
            RPCError::SSZDecodeError(ref err) => write!(f, "Error while decoding ssz: {:?}", err),
            RPCError::InvalidProtocol(ref err) => write!(f, "Invalid Protocol: {}", err),
            RPCError::IoError(ref err) => write!(f, "IO Error: {}", err),
            RPCError::StreamTimeout => write!(f, "Stream Timeout"),
            RPCError::Custom(ref err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for RPCError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            RPCError::ReadError(ref err) => Some(err),
            RPCError::SSZDecodeError(ref err) => None,
            RPCError::InvalidProtocol(ref err) => None,
            RPCError::IoError(ref err) => Some(err),
            RPCError::StreamTimeout => None,
            RPCError::Custom(ref err) => None,
        }
    }
}
