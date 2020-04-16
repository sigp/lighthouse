#![allow(clippy::type_complexity)]

use super::methods::*;
use crate::rpc::{
    codec::{
        base::{BaseInboundCodec, BaseOutboundCodec},
        ssz::{SSZInboundCodec, SSZOutboundCodec},
        ssz_snappy::{SSZSnappyInboundCodec, SSZSnappyOutboundCodec},
        InboundCodec, OutboundCodec,
    },
    methods::ResponseTermination,
};
use futures::future::*;
use futures::{future, sink, stream, Sink, Stream};
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, ProtocolName, UpgradeInfo};
use std::io;
use std::marker::PhantomData;
use std::time::Duration;
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::timeout;
use tokio::util::FutureExt;
use tokio_io_timeout::TimeoutStream;
use types::EthSpec;

/// The maximum bytes that can be sent across the RPC.
const MAX_RPC_SIZE: usize = 1_048_576; // 1M
/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth2/beacon_chain/req";
/// Time allowed for the first byte of a request to arrive before we time out (Time To First Byte).
const TTFB_TIMEOUT: u64 = 5;
/// The number of seconds to wait for the first bytes of a request once a protocol has been
/// established before the stream is terminated.
const REQUEST_TIMEOUT: u64 = 15;

/// Protocol names to be used.
/// The Status protocol name.
pub const RPC_STATUS: &str = "status";
/// The Goodbye protocol name.
pub const RPC_GOODBYE: &str = "goodbye";
/// The `BlocksByRange` protocol name.
pub const RPC_BLOCKS_BY_RANGE: &str = "beacon_blocks_by_range";
/// The `BlocksByRoot` protocol name.
pub const RPC_BLOCKS_BY_ROOT: &str = "beacon_blocks_by_root";
/// The `Ping` protocol name.
pub const RPC_PING: &str = "ping";
/// The `MetaData` protocol name.
pub const RPC_META_DATA: &str = "metadata";

#[derive(Debug, Clone)]
pub struct RPCProtocol<TSpec: EthSpec> {
    pub phantom: PhantomData<TSpec>,
}

impl<TSpec: EthSpec> UpgradeInfo for RPCProtocol<TSpec> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    /// The list of supported RPC protocols for Lighthouse.
    fn protocol_info(&self) -> Self::InfoIter {
        vec![
            ProtocolId::new(RPC_STATUS, "1", "ssz_snappy"),
            ProtocolId::new(RPC_STATUS, "1", "ssz"),
            ProtocolId::new(RPC_GOODBYE, "1", "ssz_snappy"),
            ProtocolId::new(RPC_GOODBYE, "1", "ssz"),
            ProtocolId::new(RPC_BLOCKS_BY_RANGE, "1", "ssz_snappy"),
            ProtocolId::new(RPC_BLOCKS_BY_RANGE, "1", "ssz"),
            ProtocolId::new(RPC_BLOCKS_BY_ROOT, "1", "ssz_snappy"),
            ProtocolId::new(RPC_BLOCKS_BY_ROOT, "1", "ssz"),
            ProtocolId::new(RPC_PING, "1", "ssz_snappy"),
            ProtocolId::new(RPC_PING, "1", "ssz"),
            ProtocolId::new(RPC_META_DATA, "1", "ssz_snappy"),
            ProtocolId::new(RPC_META_DATA, "1", "ssz"),
        ]
    }
}

/// Tracks the types in a protocol id.
#[derive(Clone, Debug)]
pub struct ProtocolId {
    /// The rpc message type/name.
    pub message_name: String,

    /// The version of the RPC.
    pub version: String,

    /// The encoding of the RPC.
    pub encoding: String,

    /// The protocol id that is formed from the above fields.
    protocol_id: String,
}

/// An RPC protocol ID.
impl ProtocolId {
    pub fn new(message_name: &str, version: &str, encoding: &str) -> Self {
        let protocol_id = format!(
            "{}/{}/{}/{}",
            PROTOCOL_PREFIX, message_name, version, encoding
        );

        ProtocolId {
            message_name: message_name.into(),
            version: version.into(),
            encoding: encoding.into(),
            protocol_id,
        }
    }
}

impl ProtocolName for ProtocolId {
    fn protocol_name(&self) -> &[u8] {
        self.protocol_id.as_bytes()
    }
}

/* Inbound upgrade */

// The inbound protocol reads the request, decodes it and returns the stream to the protocol
// handler to respond to once ready.

pub type InboundOutput<TSocket, TSpec> = (RPCRequest<TSpec>, InboundFramed<TSocket, TSpec>);
pub type InboundFramed<TSocket, TSpec> =
    Framed<TimeoutStream<upgrade::Negotiated<TSocket>>, InboundCodec<TSpec>>;
type FnAndThen<TSocket, TSpec> = fn(
    (Option<RPCRequest<TSpec>>, InboundFramed<TSocket, TSpec>),
) -> FutureResult<InboundOutput<TSocket, TSpec>, RPCError>;
type FnMapErr<TSocket, TSpec> =
    fn(timeout::Error<(RPCError, InboundFramed<TSocket, TSpec>)>) -> RPCError;

impl<TSocket, TSpec> InboundUpgrade<TSocket> for RPCProtocol<TSpec>
where
    TSocket: AsyncRead + AsyncWrite,
    TSpec: EthSpec,
{
    type Output = InboundOutput<TSocket, TSpec>;
    type Error = RPCError;

    type Future = future::Either<
        FutureResult<InboundOutput<TSocket, TSpec>, RPCError>,
        future::AndThen<
            future::MapErr<
                timeout::Timeout<stream::StreamFuture<InboundFramed<TSocket, TSpec>>>,
                FnMapErr<TSocket, TSpec>,
            >,
            FutureResult<InboundOutput<TSocket, TSpec>, RPCError>,
            FnAndThen<TSocket, TSpec>,
        >,
    >;

    fn upgrade_inbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: ProtocolId,
    ) -> Self::Future {
        let protocol_name = protocol.message_name.clone();
        let codec = match protocol.encoding.as_str() {
            "ssz_snappy" => {
                let ssz_snappy_codec =
                    BaseInboundCodec::new(SSZSnappyInboundCodec::new(protocol, MAX_RPC_SIZE));
                InboundCodec::SSZSnappy(ssz_snappy_codec)
            }
            "ssz" | _ => {
                let ssz_codec = BaseInboundCodec::new(SSZInboundCodec::new(protocol, MAX_RPC_SIZE));
                InboundCodec::SSZ(ssz_codec)
            }
        };
        let mut timed_socket = TimeoutStream::new(socket);
        timed_socket.set_read_timeout(Some(Duration::from_secs(TTFB_TIMEOUT)));

        let socket = Framed::new(timed_socket, codec);

        // MetaData requests should be empty, return the stream
        if protocol_name == RPC_META_DATA {
            futures::future::Either::A(futures::future::ok((
                RPCRequest::MetaData(PhantomData),
                socket,
            )))
        } else {
            futures::future::Either::B(
                socket
                    .into_future()
                    .timeout(Duration::from_secs(REQUEST_TIMEOUT))
                    .map_err(RPCError::from as FnMapErr<TSocket, TSpec>)
                    .and_then({
                        |(req, stream)| match req {
                            Some(request) => futures::future::ok((request, stream)),
                            None => futures::future::err(RPCError::Custom(
                                "Stream terminated early".into(),
                            )),
                        }
                    } as FnAndThen<TSocket, TSpec>),
            )
        }
    }
}

/* Outbound request */

// Combines all the RPC requests into a single enum to implement `UpgradeInfo` and
// `OutboundUpgrade`

#[derive(Debug, Clone, PartialEq)]
pub enum RPCRequest<TSpec: EthSpec> {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    BlocksByRange(BlocksByRangeRequest),
    BlocksByRoot(BlocksByRootRequest),
    Ping(Ping),
    MetaData(PhantomData<TSpec>),
}

impl<TSpec: EthSpec> UpgradeInfo for RPCRequest<TSpec> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        self.supported_protocols()
    }
}

/// Implements the encoding per supported protocol for RPCRequest.
impl<TSpec: EthSpec> RPCRequest<TSpec> {
    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            RPCRequest::Status(_) => vec![
                ProtocolId::new(RPC_STATUS, "1", "ssz_snappy"),
                ProtocolId::new(RPC_STATUS, "1", "ssz"),
            ],
            RPCRequest::Goodbye(_) => vec![
                ProtocolId::new(RPC_GOODBYE, "1", "ssz_snappy"),
                ProtocolId::new(RPC_GOODBYE, "1", "ssz"),
            ],
            RPCRequest::BlocksByRange(_) => vec![
                ProtocolId::new(RPC_BLOCKS_BY_RANGE, "1", "ssz_snappy"),
                ProtocolId::new(RPC_BLOCKS_BY_RANGE, "1", "ssz"),
            ],
            RPCRequest::BlocksByRoot(_) => vec![
                ProtocolId::new(RPC_BLOCKS_BY_ROOT, "1", "ssz_snappy"),
                ProtocolId::new(RPC_BLOCKS_BY_ROOT, "1", "ssz"),
            ],
            RPCRequest::Ping(_) => vec![
                ProtocolId::new(RPC_PING, "1", "ssz_snappy"),
                ProtocolId::new(RPC_PING, "1", "ssz"),
            ],
            RPCRequest::MetaData(_) => vec![
                ProtocolId::new(RPC_META_DATA, "1", "ssz_snappy"),
                ProtocolId::new(RPC_META_DATA, "1", "ssz"),
            ],
        }
    }

    /* These functions are used in the handler for stream management */

    /// This specifies whether a stream should remain open and await a response, given a request.
    /// A GOODBYE request has no response.
    pub fn expect_response(&self) -> bool {
        match self {
            RPCRequest::Status(_) => true,
            RPCRequest::Goodbye(_) => false,
            RPCRequest::BlocksByRange(_) => true,
            RPCRequest::BlocksByRoot(_) => true,
            RPCRequest::Ping(_) => true,
            RPCRequest::MetaData(_) => true,
        }
    }

    /// Returns which methods expect multiple responses from the stream. If this is false and
    /// the stream terminates, an error is given.
    pub fn multiple_responses(&self) -> bool {
        match self {
            RPCRequest::Status(_) => false,
            RPCRequest::Goodbye(_) => false,
            RPCRequest::BlocksByRange(_) => true,
            RPCRequest::BlocksByRoot(_) => true,
            RPCRequest::Ping(_) => false,
            RPCRequest::MetaData(_) => false,
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            RPCRequest::BlocksByRange(_) => ResponseTermination::BlocksByRange,
            RPCRequest::BlocksByRoot(_) => ResponseTermination::BlocksByRoot,
            RPCRequest::Status(_) => unreachable!(),
            RPCRequest::Goodbye(_) => unreachable!(),
            RPCRequest::Ping(_) => unreachable!(),
            RPCRequest::MetaData(_) => unreachable!(),
        }
    }
}

/* RPC Response type - used for outbound upgrades */

/* Outbound upgrades */

pub type OutboundFramed<TSocket, TSpec> =
    Framed<upgrade::Negotiated<TSocket>, OutboundCodec<TSpec>>;

impl<TSocket, TSpec> OutboundUpgrade<TSocket> for RPCRequest<TSpec>
where
    TSpec: EthSpec,
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = OutboundFramed<TSocket, TSpec>;
    type Error = RPCError;
    type Future = sink::Send<OutboundFramed<TSocket, TSpec>>;
    fn upgrade_outbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: Self::Info,
    ) -> Self::Future {
        let codec = match protocol.encoding.as_str() {
            "ssz_snappy" => {
                let ssz_snappy_codec =
                    BaseOutboundCodec::new(SSZSnappyOutboundCodec::new(protocol, MAX_RPC_SIZE));
                OutboundCodec::SSZSnappy(ssz_snappy_codec)
            }
            "ssz" | _ => {
                let ssz_codec =
                    BaseOutboundCodec::new(SSZOutboundCodec::new(protocol, MAX_RPC_SIZE));
                OutboundCodec::SSZ(ssz_codec)
            }
        };
        Framed::new(socket, codec).send(self)
    }
}

/// Error in RPC Encoding/Decoding.
#[derive(Debug)]
pub enum RPCError {
    /// Error when reading the packet from the socket.
    ReadError(upgrade::ReadOneError),
    /// Error when decoding the raw buffer from ssz.
    SSZDecodeError(ssz::DecodeError),
    /// Snappy error
    SnappyError(snap::Error),
    /// Invalid Protocol ID.
    InvalidProtocol(&'static str),
    /// IO Error.
    IoError(io::Error),
    /// Waiting for a request/response timed out, or timer error'd.
    StreamTimeout,
    /// The peer returned a valid RPCErrorResponse but the response was an error.
    RPCErrorResponse,
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

impl From<()> for RPCError {
    fn from(_err: ()) -> Self {
        RPCError::Custom("".into())
    }
}

impl From<io::Error> for RPCError {
    fn from(err: io::Error) -> Self {
        RPCError::IoError(err)
    }
}

impl From<snap::Error> for RPCError {
    fn from(err: snap::Error) -> Self {
        RPCError::SnappyError(err)
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
            RPCError::RPCErrorResponse => write!(f, "RPC Response Error"),
            RPCError::StreamTimeout => write!(f, "Stream Timeout"),
            RPCError::SnappyError(ref err) => write!(f, "Snappy error: {}", err),
            RPCError::Custom(ref err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for RPCError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            RPCError::ReadError(ref err) => Some(err),
            RPCError::SSZDecodeError(_) => None,
            RPCError::SnappyError(ref err) => Some(err),
            RPCError::InvalidProtocol(_) => None,
            RPCError::IoError(ref err) => Some(err),
            RPCError::StreamTimeout => None,
            RPCError::RPCErrorResponse => None,
            RPCError::Custom(_) => None,
        }
    }
}

impl<TSpec: EthSpec> std::fmt::Display for RPCRequest<TSpec> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCRequest::Status(status) => write!(f, "Status Message: {}", status),
            RPCRequest::Goodbye(reason) => write!(f, "Goodbye: {}", reason),
            RPCRequest::BlocksByRange(req) => write!(f, "Blocks by range: {}", req),
            RPCRequest::BlocksByRoot(req) => write!(f, "Blocks by root: {:?}", req),
            RPCRequest::Ping(ping) => write!(f, "Ping: {}", ping.data),
            RPCRequest::MetaData(_) => write!(f, "MetaData request"),
        }
    }
}
