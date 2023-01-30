use super::methods::*;
use crate::rpc::{
    codec::{base::BaseInboundCodec, ssz_snappy::SSZSnappyInboundCodec, InboundCodec},
    methods::{MaxErrorLen, ResponseTermination, MAX_ERROR_LEN},
    MaxRequestBlocks, MAX_REQUEST_BLOCKS,
};
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, StreamExt};
use libp2p::core::{InboundUpgrade, ProtocolName, UpgradeInfo};
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
    /// with `MAX_RPC_SIZE_POST_MERGE`.
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

/// The maximum bytes that can be sent across the RPC pre-merge.
pub(crate) const MAX_RPC_SIZE: usize = 1_048_576; // 1M
/// The maximum bytes that can be sent across the RPC post-merge.
pub(crate) const MAX_RPC_SIZE_POST_MERGE: usize = 10 * 1_048_576; // 10M
pub(crate) const MAX_RPC_SIZE_POST_CAPELLA: usize = 10 * 1_048_576; // 10M
/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth2/beacon_chain/req";
/// Time allowed for the first byte of a request to arrive before we time out (Time To First Byte).
const TTFB_TIMEOUT: u64 = 5;
/// The number of seconds to wait for the first bytes of a request once a protocol has been
/// established before the stream is terminated.
const REQUEST_TIMEOUT: u64 = 15;

/// Returns the maximum bytes that can be sent across the RPC.
pub fn max_rpc_size(fork_context: &ForkContext) -> usize {
    match fork_context.current_fork() {
        ForkName::Altair | ForkName::Base => MAX_RPC_SIZE,
        ForkName::Merge => MAX_RPC_SIZE_POST_MERGE,
        ForkName::Capella => MAX_RPC_SIZE_POST_CAPELLA,
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
    /// The `LightClientOptimisticUpdate` protocol name.
    LightClientOptimisticUpdate,
    /// The `LightClientFinalityUpdate` protocol name.
    LightClientFinalityUpdate,
}

/// RPC Versions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// Version 1 of RPC
    V1,
    /// Version 2 of RPC
    V2,
}

/// RPC Encondings supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encoding {
    SSZSnappy,
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Encoding::SSZSnappy => "ssz_snappy",
        };
        f.write_str(repr)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Version::V1 => "1",
            Version::V2 => "2",
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
}

impl<TSpec: EthSpec> UpgradeInfo for RPCProtocol<TSpec> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    /// The list of supported RPC protocols for Lighthouse.
    fn protocol_info(&self) -> Self::InfoIter {
        let mut supported_protocols = vec![
            ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::Goodbye, Version::V1, Encoding::SSZSnappy),
            // V2 variants have higher preference then V1
            ProtocolId::new(Protocol::BlocksByRange, Version::V2, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::BlocksByRange, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::BlocksByRoot, Version::V2, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::BlocksByRoot, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::Ping, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::MetaData, Version::V2, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZSnappy),
        ];
        if self.enable_light_client_server {
            supported_protocols.push(ProtocolId::new(
                Protocol::LightClientBootstrap,
                Version::V1,
                Encoding::SSZSnappy,
            ));
            supported_protocols.push(ProtocolId::new(
                Protocol::LightClientOptimisticUpdate,
                Version::V1,
                Encoding::SSZSnappy,
            ));
            supported_protocols.push(ProtocolId::new(
                Protocol::LightClientFinalityUpdate,
                Version::V1,
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
    /// The RPC message type/name.
    pub message_name: Protocol,

    /// The version of the RPC.
    pub version: Version,

    /// The encoding of the RPC.
    pub encoding: Encoding,

    /// The protocol id that is formed from the above fields.
    protocol_id: String,
}

impl ProtocolId {
    /// Returns min and max size for messages of given protocol id requests.
    pub fn rpc_request_limits(&self) -> RpcLimits {
        match self.message_name {
            Protocol::Status => RpcLimits::new(
                <StatusMessage as Encode>::ssz_fixed_len(),
                <StatusMessage as Encode>::ssz_fixed_len(),
            ),
            Protocol::Goodbye => RpcLimits::new(
                <GoodbyeReason as Encode>::ssz_fixed_len(),
                <GoodbyeReason as Encode>::ssz_fixed_len(),
            ),
            Protocol::BlocksByRange => RpcLimits::new(
                <OldBlocksByRangeRequest as Encode>::ssz_fixed_len(),
                <OldBlocksByRangeRequest as Encode>::ssz_fixed_len(),
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
            Protocol::LightClientOptimisticUpdate => RpcLimits::new(
                <LightClientOptimisticUpdateRequest as Encode>::ssz_fixed_len(),
                <LightClientOptimisticUpdateRequest as Encode>::ssz_fixed_len(),
            ),
            Protocol::LightClientFinalityUpdate => RpcLimits::new(
                <LightClientFinalityUpdateRequest as Encode>::ssz_fixed_len(),
                <LightClientFinalityUpdateRequest as Encode>::ssz_fixed_len(),
            ),
            Protocol::MetaData => RpcLimits::new(0, 0), // Metadata requests are empty
        }
    }

    /// Returns min and max size for messages of given protocol id responses.
    pub fn rpc_response_limits<T: EthSpec>(&self, fork_context: &ForkContext) -> RpcLimits {
        match self.message_name {
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
            Protocol::LightClientOptimisticUpdate => RpcLimits::new(
                <LightClientOptimisticUpdateRequest as Encode>::ssz_fixed_len(),
                <LightClientOptimisticUpdateRequest as Encode>::ssz_fixed_len(),
            ),
            Protocol::LightClientFinalityUpdate => RpcLimits::new(
                <LightClientFinalityUpdateRequest as Encode>::ssz_fixed_len(),
                <LightClientFinalityUpdateRequest as Encode>::ssz_fixed_len(),
            ),
        }
    }

    /// Returns `true` if the given `ProtocolId` should expect `context_bytes` in the
    /// beginning of the stream, else returns `false`.
    pub fn has_context_bytes(&self) -> bool {
        match self.message_name {
            Protocol::BlocksByRange | Protocol::BlocksByRoot => match self.version {
                Version::V2 => true,
                Version::V1 => false,
            },
            Protocol::LightClientBootstrap => match self.version {
                Version::V2 | Version::V1 => true,
            },
            Protocol::Goodbye | Protocol::Ping | Protocol::Status | Protocol::MetaData => false,
        }
    }
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
            let protocol_name = protocol.message_name;
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
            timed_socket.set_read_timeout(Some(Duration::from_secs(TTFB_TIMEOUT)));

            let socket = Framed::new(Box::pin(timed_socket), codec);

            // MetaData requests should be empty, return the stream
            match protocol_name {
                Protocol::MetaData => Ok((InboundRequest::MetaData(PhantomData), socket)),
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
    LightClientOptimisticUpdate(LightClientOptimisticUpdateRequest),
    LightClientFinalityUpdate(LightClientFinalityUpdateRequest),
    Ping(Ping),
    MetaData(PhantomData<TSpec>),
}

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<TSpec: EthSpec> InboundRequest<TSpec> {
    /* These functions are used in the handler for stream management */

    /// Number of responses expected for this request.
    pub fn expected_responses(&self) -> u64 {
        match self {
            InboundRequest::Status(_) => 1,
            InboundRequest::Goodbye(_) => 0,
            InboundRequest::BlocksByRange(req) => req.count,
            InboundRequest::BlocksByRoot(req) => req.block_roots.len() as u64,
            InboundRequest::Ping(_) => 1,
            InboundRequest::MetaData(_) => 1,
            InboundRequest::LightClientBootstrap(_) => 1,
            InboundRequest::LightClientOptimisticUpdate(_) => 1,
            InboundRequest::LightClientFinalityUpdate(_) => 1,
        }
    }

    /// Gives the corresponding `Protocol` to this request.
    pub fn protocol(&self) -> Protocol {
        match self {
            InboundRequest::Status(_) => Protocol::Status,
            InboundRequest::Goodbye(_) => Protocol::Goodbye,
            InboundRequest::BlocksByRange(_) => Protocol::BlocksByRange,
            InboundRequest::BlocksByRoot(_) => Protocol::BlocksByRoot,
            InboundRequest::Ping(_) => Protocol::Ping,
            InboundRequest::MetaData(_) => Protocol::MetaData,
            InboundRequest::LightClientBootstrap(_) => Protocol::LightClientBootstrap,
            InboundRequest::LightClientOptimisticUpdate(_) => Protocol::LightClientOptimisticUpdate,
            InboundRequest::LightClientFinalityUpdate(_) => Protocol::LightClientFinalityUpdate,
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
            InboundRequest::LightClientFinalityUpdate(_) => unreachable!(),
            InboundRequest::LightClientOptimisticUpdate(_) => unreachable!(),
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
            InboundRequest::LightClientOptimisticUpdate(_) => {
                write!(f, "LightClientOptimisticUpdate")
            }
            InboundRequest::LightClientFinalityUpdate(_) => {
                write!(f, "LightClientFinalityUpdate")
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
