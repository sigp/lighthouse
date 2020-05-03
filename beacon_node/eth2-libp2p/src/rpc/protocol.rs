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
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    /// The Status protocol name.
    Status,
    /// The Goodbye protocol name.
    Goodbye,
    /// The `BlocksByRange` protocol name.
    BlocksByRange,
    /// The `BlocksByRoot` protocol name.
    BlocksByRoot,
    /// The `Ping` protocol name.
    Ping,
    /// The `MetaData` protocol name.
    MetaData,
}

/// RPC Versions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// Version 1 of RPC
    V1,
}

/// RPC Encondings supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encoding {
    SSZ,
    SSZSnappy,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Protocol::Status => "status",
            Protocol::Goodbye => "goodbye",
            Protocol::BlocksByRange => "beacon_blocks_by_range",
            Protocol::BlocksByRoot => "beacon_blocks_by_root",
            Protocol::Ping => "ping",
            Protocol::MetaData => "metadata",
        };
        f.write_str(repr)
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Encoding::SSZ => "ssz",
            Encoding::SSZSnappy => "ssz_snappy",
        };
        f.write_str(repr)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Version::V1 => "1",
        };
        f.write_str(repr)
    }
}

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
            ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZ),
            ProtocolId::new(Protocol::Goodbye, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::Goodbye, Version::V1, Encoding::SSZ),
            ProtocolId::new(Protocol::BlocksByRange, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::BlocksByRange, Version::V1, Encoding::SSZ),
            ProtocolId::new(Protocol::BlocksByRoot, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::BlocksByRoot, Version::V1, Encoding::SSZ),
            ProtocolId::new(Protocol::Ping, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::Ping, Version::V1, Encoding::SSZ),
            ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZ),
        ]
    }
}

/// Tracks the types in a protocol id.
#[derive(Clone, Debug)]
pub struct ProtocolId {
    /// The RPC message type/name.
    pub message_name: Protocol,

    /// The version of the RPC.
    pub version: Version,

    /// The encoding of the RPC.
    pub encoding: Encoding,

    /// The protocol id that is formed from the above fields.
    protocol_id: String,
}

/// An RPC protocol ID.
impl ProtocolId {
    pub fn new(message_name: Protocol, version: Version, encoding: Encoding) -> Self {
        let protocol_id = format!(
            "{}/{}/{}/{}",
            PROTOCOL_PREFIX, message_name, version, encoding
        );

        ProtocolId {
            message_name,
            version,
            encoding,
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

// Auxiliary types

// The type of the socket timeout in the `InboundUpgrade` type `Future`
type TTimeout<TSocket, TSpec> =
    timeout::Timeout<stream::StreamFuture<InboundFramed<TSocket, TSpec>>>;
// The type of the socket timeout error in the `InboundUpgrade` type `Future`
type TTimeoutErr<TSocket, TSpec> = timeout::Error<(RPCError, InboundFramed<TSocket, TSpec>)>;
// `TimeoutErr` to `RPCError` mapping function
type FnMapErr<TSocket, TSpec> = fn(TTimeoutErr<TSocket, TSpec>) -> RPCError;

type FnAndThen<TSocket, TSpec> = fn(
    (Option<RPCRequest<TSpec>>, InboundFramed<TSocket, TSpec>),
) -> FutureResult<InboundOutput<TSocket, TSpec>, RPCError>;

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
            future::MapErr<TTimeout<TSocket, TSpec>, FnMapErr<TSocket, TSpec>>,
            FutureResult<InboundOutput<TSocket, TSpec>, RPCError>,
            FnAndThen<TSocket, TSpec>,
        >,
    >;

    fn upgrade_inbound(
        self,
        socket: upgrade::Negotiated<TSocket>,
        protocol: ProtocolId,
    ) -> Self::Future {
        let protocol_name = protocol.message_name;
        let codec = match protocol.encoding {
            Encoding::SSZSnappy => {
                let ssz_snappy_codec =
                    BaseInboundCodec::new(SSZSnappyInboundCodec::new(protocol, MAX_RPC_SIZE));
                InboundCodec::SSZSnappy(ssz_snappy_codec)
            }
            Encoding::SSZ => {
                let ssz_codec = BaseInboundCodec::new(SSZInboundCodec::new(protocol, MAX_RPC_SIZE));
                InboundCodec::SSZ(ssz_codec)
            }
        };
        let mut timed_socket = TimeoutStream::new(socket);
        timed_socket.set_read_timeout(Some(Duration::from_secs(TTFB_TIMEOUT)));

        let socket = Framed::new(timed_socket, codec);

        match protocol_name {
            // `MetaData` requests should be empty, return the stream
            Protocol::MetaData => {
                future::Either::A(future::ok((RPCRequest::MetaData(PhantomData), socket)))
            }
            _ => future::Either::B({
                socket
                    .into_future()
                    .timeout(Duration::from_secs(REQUEST_TIMEOUT))
                    .map_err({
                        |err| {
                            if err.is_elapsed() {
                                RPCError::StreamTimeout
                            } else {
                                RPCError::InternalError("Stream timer failed")
                            }
                        }
                    } as FnMapErr<TSocket, TSpec>)
                    .and_then({
                        |(req, stream)| match req {
                            Some(request) => future::ok((request, stream)),
                            None => future::err(RPCError::IncompleteStream),
                        }
                    } as FnAndThen<TSocket, TSpec>)
            }),
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

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<TSpec: EthSpec> RPCRequest<TSpec> {
    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            RPCRequest::Status(_) => vec![
                ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZ),
            ],
            RPCRequest::Goodbye(_) => vec![
                ProtocolId::new(Protocol::Goodbye, Version::V1, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::Goodbye, Version::V1, Encoding::SSZ),
            ],
            RPCRequest::BlocksByRange(_) => vec![
                ProtocolId::new(Protocol::BlocksByRange, Version::V1, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::BlocksByRange, Version::V1, Encoding::SSZ),
            ],
            RPCRequest::BlocksByRoot(_) => vec![
                ProtocolId::new(Protocol::BlocksByRoot, Version::V1, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::BlocksByRoot, Version::V1, Encoding::SSZ),
            ],
            RPCRequest::Ping(_) => vec![
                ProtocolId::new(Protocol::Ping, Version::V1, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::Ping, Version::V1, Encoding::SSZ),
            ],
            RPCRequest::MetaData(_) => vec![
                ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZ),
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

    pub fn protocol(&self) -> Protocol {
        match self {
            RPCRequest::Status(_) => Protocol::Status,
            RPCRequest::Goodbye(_) => Protocol::Goodbye,
            RPCRequest::BlocksByRange(_) => Protocol::BlocksByRange,
            RPCRequest::BlocksByRoot(_) => Protocol::BlocksByRoot,
            RPCRequest::Ping(_) => Protocol::Ping,
            RPCRequest::MetaData(_) => Protocol::MetaData,
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
        let codec = match protocol.encoding {
            Encoding::SSZSnappy => {
                let ssz_snappy_codec =
                    BaseOutboundCodec::new(SSZSnappyOutboundCodec::new(protocol, MAX_RPC_SIZE));
                OutboundCodec::SSZSnappy(ssz_snappy_codec)
            }
            Encoding::SSZ => {
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
    /// Error when decoding the raw buffer from ssz.
    // NOTE: in the future a ssz::DecodeError should map to an InvalidData error
    SSZDecodeError(ssz::DecodeError),
    /// IO Error.
    IoError(io::Error),
    /// The peer returned a valid response but the response indicated an error.
    ErrorResponse(RPCResponseErrorCode),
    /// Timed out waiting for a response.
    StreamTimeout,
    /// Peer does not support the protocol.
    UnsupportedProtocol,
    /// Stream ended unexpectedly.
    IncompleteStream,
    /// Peer sent invalid data.
    InvalidData,
    /// An error occurred due to internal reasons. Ex: timer failure.
    InternalError(&'static str),
    /// Negotiation with this peer timed out
    NegotiationTimeout,
}

impl From<ssz::DecodeError> for RPCError {
    #[inline]
    fn from(err: ssz::DecodeError) -> Self {
        RPCError::SSZDecodeError(err)
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
            RPCError::SSZDecodeError(ref err) => write!(f, "Error while decoding ssz: {:?}", err),
            RPCError::InvalidData => write!(f, "Peer sent unexpected data"),
            RPCError::IoError(ref err) => write!(f, "IO Error: {}", err),
            RPCError::ErrorResponse(ref code) => write!(f, "RPC response was an error: {}", code),
            RPCError::StreamTimeout => write!(f, "Stream Timeout"),
            RPCError::UnsupportedProtocol => write!(f, "Peer does not support the protocol"),
            RPCError::IncompleteStream => write!(f, "Stream ended unexpectedly"),
            RPCError::InternalError(ref err) => write!(f, "Internal error: {}", err),
            RPCError::NegotiationTimeout => write!(f, "Negotiation timeout"),
        }
    }
}

impl std::error::Error for RPCError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            // NOTE: this does have a source
            RPCError::SSZDecodeError(_) => None,
            RPCError::IoError(ref err) => Some(err),
            RPCError::StreamTimeout => None,
            RPCError::UnsupportedProtocol => None,
            RPCError::IncompleteStream => None,
            RPCError::InvalidData => None,
            RPCError::InternalError(_) => None,
            RPCError::ErrorResponse(_) => None,
            RPCError::NegotiationTimeout => None,
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
