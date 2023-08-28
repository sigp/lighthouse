use super::methods::*;
use crate::rpc::{
    codec::{base::BaseInboundCodec, ssz_snappy::SSZSnappyInboundCodec, InboundCodec},
    methods::{MaxErrorLen, ResponseTermination, MAX_ERROR_LEN},
    MaxRequestBlocks, MAX_REQUEST_BLOCKS,
};
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, StreamExt};
use libp2p::core::{InboundUpgrade, UpgradeInfo};
use ssz::Encode;
use ssz_types::VariableList;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use strum::{AsRefStr, Display, EnumString, IntoStaticStr};
use tokio_io_timeout::TimeoutStream;
use tokio_util::{
    codec::Framed,
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use types::{
    BeaconBlock, BeaconBlockAltair, BeaconBlockBase, BeaconBlockCapella, BeaconBlockMerge,
    EmptyBlock, EthSpec, ForkContext, ForkName, Hash256, MainnetEthSpec, Signature,
    SignedBeaconBlock,
};

lazy_static! {
    // Note: Hardcoding the `EthSpec` type for `SignedBeaconBlock` as min/max values is
    // same across different `EthSpec` implementations.
    pub static ref SIGNED_BEACON_BLOCK_BASE_MIN: usize = SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Base(BeaconBlockBase::<MainnetEthSpec>::empty(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len();
    pub static ref SIGNED_BEACON_BLOCK_BASE_MAX: usize = SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Base(BeaconBlockBase::full(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len();

    pub static ref SIGNED_BEACON_BLOCK_ALTAIR_MIN: usize = SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Altair(BeaconBlockAltair::<MainnetEthSpec>::empty(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len();
    pub static ref SIGNED_BEACON_BLOCK_ALTAIR_MAX: usize = SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Altair(BeaconBlockAltair::full(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len();

    pub static ref SIGNED_BEACON_BLOCK_MERGE_MIN: usize = SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Merge(BeaconBlockMerge::<MainnetEthSpec>::empty(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len();

    pub static ref SIGNED_BEACON_BLOCK_CAPELLA_MAX_WITHOUT_PAYLOAD: usize = SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Capella(BeaconBlockCapella::full(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len();

    /// The `BeaconBlockMerge` block has an `ExecutionPayload` field which has a max size ~16 GiB for future proofing.
    /// We calculate the value from its fields instead of constructing the block and checking the length.
    /// Note: This is only the theoretical upper bound. We further bound the max size we receive over the network
    /// with `max_chunk_size`.
    pub static ref SIGNED_BEACON_BLOCK_MERGE_MAX: usize =
    // Size of a full altair block
    *SIGNED_BEACON_BLOCK_ALTAIR_MAX
    + types::ExecutionPayload::<MainnetEthSpec>::max_execution_payload_merge_size() // adding max size of execution payload (~16gb)
    + ssz::BYTES_PER_LENGTH_OFFSET; // Adding the additional ssz offset for the `ExecutionPayload` field

    pub static ref SIGNED_BEACON_BLOCK_CAPELLA_MAX: usize = *SIGNED_BEACON_BLOCK_CAPELLA_MAX_WITHOUT_PAYLOAD
    + types::ExecutionPayload::<MainnetEthSpec>::max_execution_payload_capella_size() // adding max size of execution payload (~16gb)
    + ssz::BYTES_PER_LENGTH_OFFSET; // Adding the additional ssz offset for the `ExecutionPayload` field

    pub static ref BLOCKS_BY_ROOT_REQUEST_MIN: usize =
        VariableList::<Hash256, MaxRequestBlocks>::from(Vec::<Hash256>::new())
    .as_ssz_bytes()
    .len();
    pub static ref BLOCKS_BY_ROOT_REQUEST_MAX: usize =
        VariableList::<Hash256, MaxRequestBlocks>::from(vec![
            Hash256::zero();
            MAX_REQUEST_BLOCKS
                as usize
        ])
    .as_ssz_bytes()
    .len();
    pub static ref ERROR_TYPE_MIN: usize =
        VariableList::<u8, MaxErrorLen>::from(Vec::<u8>::new())
    .as_ssz_bytes()
    .len();
    pub static ref ERROR_TYPE_MAX: usize =
        VariableList::<u8, MaxErrorLen>::from(vec![
            0u8;
            MAX_ERROR_LEN
                as usize
        ])
    .as_ssz_bytes()
    .len();
}

/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth2/beacon_chain/req";
/// The number of seconds to wait for the first bytes of a request once a protocol has been
/// established before the stream is terminated.
const REQUEST_TIMEOUT: u64 = 15;

/// Returns the maximum bytes that can be sent across the RPC.
pub fn max_rpc_size(fork_context: &ForkContext, max_chunk_size: usize) -> usize {
    match fork_context.current_fork() {
        ForkName::Altair | ForkName::Base => max_chunk_size / 10,
        ForkName::Merge => max_chunk_size,
        ForkName::Capella => max_chunk_size,
    }
}

/// Returns the rpc limits for beacon_block_by_range and beacon_block_by_root responses.
///
/// Note: This function should take care to return the min/max limits accounting for all
/// previous valid forks when adding a new fork variant.
pub fn rpc_block_limits_by_fork(current_fork: ForkName) -> RpcLimits {
    match &current_fork {
        ForkName::Base => {
            RpcLimits::new(*SIGNED_BEACON_BLOCK_BASE_MIN, *SIGNED_BEACON_BLOCK_BASE_MAX)
        }
        ForkName::Altair => RpcLimits::new(
            *SIGNED_BEACON_BLOCK_BASE_MIN, // Base block is smaller than altair blocks
            *SIGNED_BEACON_BLOCK_ALTAIR_MAX, // Altair block is larger than base blocks
        ),
        ForkName::Merge => RpcLimits::new(
            *SIGNED_BEACON_BLOCK_BASE_MIN, // Base block is smaller than altair and merge blocks
            *SIGNED_BEACON_BLOCK_MERGE_MAX, // Merge block is larger than base and altair blocks
        ),
        ForkName::Capella => RpcLimits::new(
            *SIGNED_BEACON_BLOCK_BASE_MIN, // Base block is smaller than altair and merge blocks
            *SIGNED_BEACON_BLOCK_CAPELLA_MAX, // Capella block is larger than base, altair and merge blocks
        ),
    }
}

/// Protocol names to be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, AsRefStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Protocol {
    /// The Status protocol name.
    Status,
    /// The Goodbye protocol name.
    Goodbye,
    /// The `BlocksByRange` protocol name.
    #[strum(serialize = "beacon_blocks_by_range")]
    BlocksByRange,
    /// The `BlocksByRoot` protocol name.
    #[strum(serialize = "beacon_blocks_by_root")]
    BlocksByRoot,
    /// The `Ping` protocol name.
    Ping,
    /// The `MetaData` protocol name.
    #[strum(serialize = "metadata")]
    MetaData,
    /// The `LightClientBootstrap` protocol name.
    #[strum(serialize = "light_client_bootstrap")]
    LightClientBootstrap,
}

/// RPC Encondings supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encoding {
    SSZSnappy,
}

/// All valid protocol name and version combinations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SupportedProtocol {
    StatusV1,
    GoodbyeV1,
    BlocksByRangeV1,
    BlocksByRangeV2,
    BlocksByRootV1,
    BlocksByRootV2,
    PingV1,
    MetaDataV1,
    MetaDataV2,
    LightClientBootstrapV1,
}

impl SupportedProtocol {
    pub fn version_string(&self) -> &'static str {
        match self {
            SupportedProtocol::StatusV1 => "1",
            SupportedProtocol::GoodbyeV1 => "1",
            SupportedProtocol::BlocksByRangeV1 => "1",
            SupportedProtocol::BlocksByRangeV2 => "2",
            SupportedProtocol::BlocksByRootV1 => "1",
            SupportedProtocol::BlocksByRootV2 => "2",
            SupportedProtocol::PingV1 => "1",
            SupportedProtocol::MetaDataV1 => "1",
            SupportedProtocol::MetaDataV2 => "2",
            SupportedProtocol::LightClientBootstrapV1 => "1",
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            SupportedProtocol::StatusV1 => Protocol::Status,
            SupportedProtocol::GoodbyeV1 => Protocol::Goodbye,
            SupportedProtocol::BlocksByRangeV1 => Protocol::BlocksByRange,
            SupportedProtocol::BlocksByRangeV2 => Protocol::BlocksByRange,
            SupportedProtocol::BlocksByRootV1 => Protocol::BlocksByRoot,
            SupportedProtocol::BlocksByRootV2 => Protocol::BlocksByRoot,
            SupportedProtocol::PingV1 => Protocol::Ping,
            SupportedProtocol::MetaDataV1 => Protocol::MetaData,
            SupportedProtocol::MetaDataV2 => Protocol::MetaData,
            SupportedProtocol::LightClientBootstrapV1 => Protocol::LightClientBootstrap,
        }
    }

    fn currently_supported() -> Vec<ProtocolId> {
        vec![
            ProtocolId::new(Self::StatusV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::GoodbyeV1, Encoding::SSZSnappy),
            // V2 variants have higher preference then V1
            ProtocolId::new(Self::BlocksByRangeV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRangeV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::PingV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::MetaDataV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::MetaDataV1, Encoding::SSZSnappy),
        ]
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Encoding::SSZSnappy => "ssz_snappy",
        };
        f.write_str(repr)
    }
}

#[derive(Debug, Clone)]
pub struct RPCProtocol<TSpec: EthSpec> {
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
    pub enable_light_client_server: bool,
    pub phantom: PhantomData<TSpec>,
    pub ttfb_timeout: Duration,
}

impl<TSpec: EthSpec> UpgradeInfo for RPCProtocol<TSpec> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    /// The list of supported RPC protocols for Lighthouse.
    fn protocol_info(&self) -> Self::InfoIter {
        let mut supported_protocols = SupportedProtocol::currently_supported();
        if self.enable_light_client_server {
            supported_protocols.push(ProtocolId::new(
                SupportedProtocol::LightClientBootstrapV1,
                Encoding::SSZSnappy,
            ));
        }
        supported_protocols
    }
}

/// Represents the ssz length bounds for RPC messages.
#[derive(Debug, PartialEq)]
pub struct RpcLimits {
    pub min: usize,
    pub max: usize,
}

impl RpcLimits {
    pub fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }

    /// Returns true if the given length is greater than `max_rpc_size` or out of
    /// bounds for the given ssz type, returns false otherwise.
    pub fn is_out_of_bounds(&self, length: usize, max_rpc_size: usize) -> bool {
        length > std::cmp::min(self.max, max_rpc_size) || length < self.min
    }
}

/// Tracks the types in a protocol id.
#[derive(Clone, Debug)]
pub struct ProtocolId {
    /// The protocol name and version
    pub versioned_protocol: SupportedProtocol,

    /// The encoding of the RPC.
    pub encoding: Encoding,

    /// The protocol id that is formed from the above fields.
    protocol_id: String,
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        self.protocol_id.as_ref()
    }
}

impl ProtocolId {
    /// Returns min and max size for messages of given protocol id requests.
    pub fn rpc_request_limits(&self) -> RpcLimits {
        match self.versioned_protocol.protocol() {
            Protocol::Status => RpcLimits::new(
                <StatusMessage as Encode>::ssz_fixed_len(),
                <StatusMessage as Encode>::ssz_fixed_len(),
            ),
            Protocol::Goodbye => RpcLimits::new(
                <GoodbyeReason as Encode>::ssz_fixed_len(),
                <GoodbyeReason as Encode>::ssz_fixed_len(),
            ),
            // V1 and V2 requests are the same
            Protocol::BlocksByRange => RpcLimits::new(
                <OldBlocksByRangeRequestV2 as Encode>::ssz_fixed_len(),
                <OldBlocksByRangeRequestV2 as Encode>::ssz_fixed_len(),
            ),
            Protocol::BlocksByRoot => {
                RpcLimits::new(*BLOCKS_BY_ROOT_REQUEST_MIN, *BLOCKS_BY_ROOT_REQUEST_MAX)
            }
            Protocol::Ping => RpcLimits::new(
                <Ping as Encode>::ssz_fixed_len(),
                <Ping as Encode>::ssz_fixed_len(),
            ),
            Protocol::LightClientBootstrap => RpcLimits::new(
                <LightClientBootstrapRequest as Encode>::ssz_fixed_len(),
                <LightClientBootstrapRequest as Encode>::ssz_fixed_len(),
            ),
            Protocol::MetaData => RpcLimits::new(0, 0), // Metadata requests are empty
        }
    }

    /// Returns min and max size for messages of given protocol id responses.
    pub fn rpc_response_limits<T: EthSpec>(&self, fork_context: &ForkContext) -> RpcLimits {
        match self.versioned_protocol.protocol() {
            Protocol::Status => RpcLimits::new(
                <StatusMessage as Encode>::ssz_fixed_len(),
                <StatusMessage as Encode>::ssz_fixed_len(),
            ),
            Protocol::Goodbye => RpcLimits::new(0, 0), // Goodbye request has no response
            Protocol::BlocksByRange => rpc_block_limits_by_fork(fork_context.current_fork()),
            Protocol::BlocksByRoot => rpc_block_limits_by_fork(fork_context.current_fork()),
            Protocol::Ping => RpcLimits::new(
                <Ping as Encode>::ssz_fixed_len(),
                <Ping as Encode>::ssz_fixed_len(),
            ),
            Protocol::MetaData => RpcLimits::new(
                <MetaDataV1<T> as Encode>::ssz_fixed_len(),
                <MetaDataV2<T> as Encode>::ssz_fixed_len(),
            ),
            Protocol::LightClientBootstrap => RpcLimits::new(
                <LightClientBootstrapRequest as Encode>::ssz_fixed_len(),
                <LightClientBootstrapRequest as Encode>::ssz_fixed_len(),
            ),
        }
    }

    /// Returns `true` if the given `ProtocolId` should expect `context_bytes` in the
    /// beginning of the stream, else returns `false`.
    pub fn has_context_bytes(&self) -> bool {
        match self.versioned_protocol {
            SupportedProtocol::BlocksByRangeV2
            | SupportedProtocol::BlocksByRootV2
            | SupportedProtocol::LightClientBootstrapV1 => true,
            SupportedProtocol::StatusV1
            | SupportedProtocol::BlocksByRootV1
            | SupportedProtocol::BlocksByRangeV1
            | SupportedProtocol::PingV1
            | SupportedProtocol::MetaDataV1
            | SupportedProtocol::MetaDataV2
            | SupportedProtocol::GoodbyeV1 => false,
        }
    }
}

/// An RPC protocol ID.
impl ProtocolId {
    pub fn new(versioned_protocol: SupportedProtocol, encoding: Encoding) -> Self {
        let protocol_id = format!(
            "{}/{}/{}/{}",
            PROTOCOL_PREFIX,
            versioned_protocol.protocol(),
            versioned_protocol.version_string(),
            encoding
        );

        ProtocolId {
            versioned_protocol,
            encoding,
            protocol_id,
        }
    }
}

/* Inbound upgrade */

// The inbound protocol reads the request, decodes it and returns the stream to the protocol
// handler to respond to once ready.

pub type InboundOutput<TSocket, TSpec> = (InboundRequest<TSpec>, InboundFramed<TSocket, TSpec>);
pub type InboundFramed<TSocket, TSpec> =
    Framed<std::pin::Pin<Box<TimeoutStream<Compat<TSocket>>>>, InboundCodec<TSpec>>;

impl<TSocket, TSpec> InboundUpgrade<TSocket> for RPCProtocol<TSpec>
where
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    TSpec: EthSpec,
{
    type Output = InboundOutput<TSocket, TSpec>;
    type Error = RPCError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: TSocket, protocol: ProtocolId) -> Self::Future {
        async move {
            let versioned_protocol = protocol.versioned_protocol;
            // convert the socket to tokio compatible socket
            let socket = socket.compat();
            let codec = match protocol.encoding {
                Encoding::SSZSnappy => {
                    let ssz_snappy_codec = BaseInboundCodec::new(SSZSnappyInboundCodec::new(
                        protocol,
                        self.max_rpc_size,
                        self.fork_context.clone(),
                    ));
                    InboundCodec::SSZSnappy(ssz_snappy_codec)
                }
            };
            let mut timed_socket = TimeoutStream::new(socket);
            timed_socket.set_read_timeout(Some(self.ttfb_timeout));

            let socket = Framed::new(Box::pin(timed_socket), codec);

            // MetaData requests should be empty, return the stream
            match versioned_protocol {
                SupportedProtocol::MetaDataV1 => {
                    Ok((InboundRequest::MetaData(MetadataRequest::new_v1()), socket))
                }
                SupportedProtocol::MetaDataV2 => {
                    Ok((InboundRequest::MetaData(MetadataRequest::new_v2()), socket))
                }
                _ => {
                    match tokio::time::timeout(
                        Duration::from_secs(REQUEST_TIMEOUT),
                        socket.into_future(),
                    )
                    .await
                    {
                        Err(e) => Err(RPCError::from(e)),
                        Ok((Some(Ok(request)), stream)) => Ok((request, stream)),
                        Ok((Some(Err(e)), _)) => Err(e),
                        Ok((None, _)) => Err(RPCError::IncompleteStream),
                    }
                }
            }
        }
        .boxed()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InboundRequest<TSpec: EthSpec> {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    BlocksByRange(OldBlocksByRangeRequest),
    BlocksByRoot(BlocksByRootRequest),
    LightClientBootstrap(LightClientBootstrapRequest),
    Ping(Ping),
    MetaData(MetadataRequest<TSpec>),
}

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<TSpec: EthSpec> InboundRequest<TSpec> {
    /* These functions are used in the handler for stream management */

    /// Number of responses expected for this request.
    pub fn expected_responses(&self) -> u64 {
        match self {
            InboundRequest::Status(_) => 1,
            InboundRequest::Goodbye(_) => 0,
            InboundRequest::BlocksByRange(req) => *req.count(),
            InboundRequest::BlocksByRoot(req) => req.block_roots().len() as u64,
            InboundRequest::Ping(_) => 1,
            InboundRequest::MetaData(_) => 1,
            InboundRequest::LightClientBootstrap(_) => 1,
        }
    }

    /// Gives the corresponding `SupportedProtocol` to this request.
    pub fn versioned_protocol(&self) -> SupportedProtocol {
        match self {
            InboundRequest::Status(_) => SupportedProtocol::StatusV1,
            InboundRequest::Goodbye(_) => SupportedProtocol::GoodbyeV1,
            InboundRequest::BlocksByRange(req) => match req {
                OldBlocksByRangeRequest::V1(_) => SupportedProtocol::BlocksByRangeV1,
                OldBlocksByRangeRequest::V2(_) => SupportedProtocol::BlocksByRangeV2,
            },
            InboundRequest::BlocksByRoot(req) => match req {
                BlocksByRootRequest::V1(_) => SupportedProtocol::BlocksByRootV1,
                BlocksByRootRequest::V2(_) => SupportedProtocol::BlocksByRootV2,
            },
            InboundRequest::Ping(_) => SupportedProtocol::PingV1,
            InboundRequest::MetaData(req) => match req {
                MetadataRequest::V1(_) => SupportedProtocol::MetaDataV1,
                MetadataRequest::V2(_) => SupportedProtocol::MetaDataV2,
            },
            InboundRequest::LightClientBootstrap(_) => SupportedProtocol::LightClientBootstrapV1,
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            InboundRequest::BlocksByRange(_) => ResponseTermination::BlocksByRange,
            InboundRequest::BlocksByRoot(_) => ResponseTermination::BlocksByRoot,
            InboundRequest::Status(_) => unreachable!(),
            InboundRequest::Goodbye(_) => unreachable!(),
            InboundRequest::Ping(_) => unreachable!(),
            InboundRequest::MetaData(_) => unreachable!(),
            InboundRequest::LightClientBootstrap(_) => unreachable!(),
        }
    }
}

/// Error in RPC Encoding/Decoding.
#[derive(Debug, Clone, PartialEq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RPCError {
    /// Error when decoding the raw buffer from ssz.
    // NOTE: in the future a ssz::DecodeError should map to an InvalidData error
    #[strum(serialize = "decode_error")]
    SSZDecodeError(ssz::DecodeError),
    /// IO Error.
    IoError(String),
    /// The peer returned a valid response but the response indicated an error.
    ErrorResponse(RPCResponseErrorCode, String),
    /// Timed out waiting for a response.
    StreamTimeout,
    /// Peer does not support the protocol.
    UnsupportedProtocol,
    /// Stream ended unexpectedly.
    IncompleteStream,
    /// Peer sent invalid data.
    InvalidData(String),
    /// An error occurred due to internal reasons. Ex: timer failure.
    InternalError(&'static str),
    /// Negotiation with this peer timed out.
    NegotiationTimeout,
    /// Handler rejected this request.
    HandlerRejected,
    /// We have intentionally disconnected.
    Disconnected,
}

impl From<ssz::DecodeError> for RPCError {
    #[inline]
    fn from(err: ssz::DecodeError) -> Self {
        RPCError::SSZDecodeError(err)
    }
}
impl From<tokio::time::error::Elapsed> for RPCError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        RPCError::StreamTimeout
    }
}

impl From<io::Error> for RPCError {
    fn from(err: io::Error) -> Self {
        RPCError::IoError(err.to_string())
    }
}

// Error trait is required for `ProtocolsHandler`
impl std::fmt::Display for RPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RPCError::SSZDecodeError(ref err) => write!(f, "Error while decoding ssz: {:?}", err),
            RPCError::InvalidData(ref err) => write!(f, "Peer sent unexpected data: {}", err),
            RPCError::IoError(ref err) => write!(f, "IO Error: {}", err),
            RPCError::ErrorResponse(ref code, ref reason) => write!(
                f,
                "RPC response was an error: {} with reason: {}",
                code, reason
            ),
            RPCError::StreamTimeout => write!(f, "Stream Timeout"),
            RPCError::UnsupportedProtocol => write!(f, "Peer does not support the protocol"),
            RPCError::IncompleteStream => write!(f, "Stream ended unexpectedly"),
            RPCError::InternalError(ref err) => write!(f, "Internal error: {}", err),
            RPCError::NegotiationTimeout => write!(f, "Negotiation timeout"),
            RPCError::HandlerRejected => write!(f, "Handler rejected the request"),
            RPCError::Disconnected => write!(f, "Gracefully Disconnected"),
        }
    }
}

impl std::error::Error for RPCError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            // NOTE: this does have a source
            RPCError::SSZDecodeError(_) => None,
            RPCError::IoError(_) => None,
            RPCError::StreamTimeout => None,
            RPCError::UnsupportedProtocol => None,
            RPCError::IncompleteStream => None,
            RPCError::InvalidData(_) => None,
            RPCError::InternalError(_) => None,
            RPCError::ErrorResponse(_, _) => None,
            RPCError::NegotiationTimeout => None,
            RPCError::HandlerRejected => None,
            RPCError::Disconnected => None,
        }
    }
}

impl<TSpec: EthSpec> std::fmt::Display for InboundRequest<TSpec> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InboundRequest::Status(status) => write!(f, "Status Message: {}", status),
            InboundRequest::Goodbye(reason) => write!(f, "Goodbye: {}", reason),
            InboundRequest::BlocksByRange(req) => write!(f, "Blocks by range: {}", req),
            InboundRequest::BlocksByRoot(req) => write!(f, "Blocks by root: {:?}", req),
            InboundRequest::Ping(ping) => write!(f, "Ping: {}", ping.data),
            InboundRequest::MetaData(_) => write!(f, "MetaData request"),
            InboundRequest::LightClientBootstrap(bootstrap) => {
                write!(f, "LightClientBootstrap: {}", bootstrap.root)
            }
        }
    }
}

impl RPCError {
    /// Get a `str` representation of the error.
    /// Used for metrics.
    pub fn as_static_str(&self) -> &'static str {
        match self {
            RPCError::ErrorResponse(ref code, ..) => code.into(),
            e => e.into(),
        }
    }
}
