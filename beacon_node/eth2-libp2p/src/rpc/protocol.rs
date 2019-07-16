use super::methods::*;
use crate::rpc::codec::{
    base::{BaseInboundCodec, BaseOutboundCodec},
    ssz::{SSZInboundCodec, SSZOutboundCodec},
    InboundCodec, OutboundCodec,
};
use futures::{
    future::{self, FutureResult},
    sink, stream, Sink, Stream,
};
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use std::io;
use std::time::Duration;
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::prelude::*;
use tokio::timer::timeout;
use tokio::util::FutureExt;

/// The maximum bytes that can be sent across the RPC.
const MAX_RPC_SIZE: usize = 4_194_304; // 4M
/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth/serenity/rpc/";
/// The number of seconds to wait for a request once a protocol has been established before the stream is terminated.
const REQUEST_TIMEOUT: u64 = 3;

/// Implementation of the `ConnectionUpgrade` for the RPC protocol.
#[derive(Debug, Clone)]
pub struct RPCProtocol;

impl UpgradeInfo for RPCProtocol {
    type Info = RawProtocolId;
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![
            ProtocolId::new("hello", "1.0.0", "ssz").into(),
            ProtocolId::new("goodbye", "1.0.0", "ssz").into(),
            ProtocolId::new("beacon_block_roots", "1.0.0", "ssz").into(),
            ProtocolId::new("beacon_block_headers", "1.0.0", "ssz").into(),
            ProtocolId::new("beacon_block_bodies", "1.0.0", "ssz").into(),
            ProtocolId::new("beacon_chain_state", "1.0.0", "ssz").into(),
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

pub type InboundOutput<TSocket> = (RPCRequest, InboundFramed<TSocket>);
pub type InboundFramed<TSocket> = Framed<upgrade::Negotiated<TSocket>, InboundCodec>;
type FnAndThen<TSocket> = fn(
    (Option<RPCRequest>, InboundFramed<TSocket>),
) -> FutureResult<InboundOutput<TSocket>, RPCError>;
type FnMapErr<TSocket> = fn(timeout::Error<(RPCError, InboundFramed<TSocket>)>) -> RPCError;

impl<TSocket> InboundUpgrade<TSocket> for RPCProtocol
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = InboundOutput<TSocket>;
    type Error = RPCError;

    type Future = future::AndThen<
        future::MapErr<
            timeout::Timeout<stream::StreamFuture<InboundFramed<TSocket>>>,
            FnMapErr<TSocket>,
        >,
        FutureResult<InboundOutput<TSocket>, RPCError>,
        FnAndThen<TSocket>,
    >;

    fn upgrade_inbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: RawProtocolId,
    ) -> Self::Future {
        // TODO: Verify this
        let protocol_id =
            ProtocolId::from_bytes(&protocol).expect("Can decode all supported protocols");

        match protocol_id.encoding.as_str() {
            "ssz" | _ => {
                let ssz_codec =
                    BaseInboundCodec::new(SSZInboundCodec::new(protocol_id, MAX_RPC_SIZE));
                let codec = InboundCodec::SSZ(ssz_codec);
                Framed::new(socket, codec)
                    .into_future()
                    .timeout(Duration::from_secs(REQUEST_TIMEOUT))
                    .map_err(RPCError::from as FnMapErr<TSocket>)
                    .and_then({
                        |(req, stream)| match req {
                            Some(req) => futures::future::ok((req, stream)),
                            None => futures::future::err(RPCError::Custom(
                                "Stream terminated early".into(),
                            )),
                        }
                    } as FnAndThen<TSocket>)
            }
        }
    }
}

/* Outbound request */

// Combines all the RPC requests into a single enum to implement `UpgradeInfo` and
// `OutboundUpgrade`

#[derive(Debug, Clone)]
pub enum RPCRequest {
    Hello(HelloMessage),
    Goodbye(GoodbyeReason),
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

    /// This specifies whether a stream should remain open and await a response, given a request.
    /// A GOODBYE request has no response.
    pub fn expect_response(&self) -> bool {
        match self {
            RPCRequest::Goodbye(_) => false,
            _ => true,
        }
    }
}

/* RPC Response type - used for outbound upgrades */

/* Outbound upgrades */

pub type OutboundFramed<TSocket> = Framed<upgrade::Negotiated<TSocket>, OutboundCodec>;

impl<TSocket> OutboundUpgrade<TSocket> for RPCRequest
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = OutboundFramed<TSocket>;
    type Error = RPCError;
    type Future = sink::Send<OutboundFramed<TSocket>>;
    fn upgrade_outbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: Self::Info,
    ) -> Self::Future {
        let protocol_id =
            ProtocolId::from_bytes(&protocol).expect("Can decode all supported protocols");

        match protocol_id.encoding.as_str() {
            "ssz" | _ => {
                let ssz_codec = BaseOutboundCodec::new(SSZOutboundCodec::new(protocol_id, 4096));
                let codec = OutboundCodec::SSZ(ssz_codec);
                Framed::new(socket, codec).send(self)
            }
        }
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
            RPCError::SSZDecodeError(_) => None,
            RPCError::InvalidProtocol(_) => None,
            RPCError::IoError(ref err) => Some(err),
            RPCError::StreamTimeout => None,
            RPCError::Custom(_) => None,
        }
    }
}
