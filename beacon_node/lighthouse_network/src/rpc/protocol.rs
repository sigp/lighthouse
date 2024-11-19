use super::methods::*;
use crate::rpc::codec::SSZSnappyInboundCodec;
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, StreamExt};
use libp2p::core::{InboundUpgrade, UpgradeInfo};
use ssz::Encode;
use ssz_types::VariableList;
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use strum::{AsRefStr, Display, EnumString, IntoStaticStr};
use tokio_io_timeout::TimeoutStream;
use tokio_util::{
    codec::Framed,
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use types::{
    BeaconBlock, BeaconBlockAltair, BeaconBlockBase, BeaconBlockCapella, BeaconBlockElectra,
    BlobSidecar, ChainSpec, DataColumnSidecar, EmptyBlock, EthSpec, EthSpecId, ForkContext,
    ForkName, LightClientBootstrap, LightClientBootstrapAltair, LightClientFinalityUpdate,
    LightClientFinalityUpdateAltair, LightClientOptimisticUpdate,
    LightClientOptimisticUpdateAltair, LightClientUpdate, MainnetEthSpec, MinimalEthSpec,
    Signature, SignedBeaconBlock,
};

// Note: Hardcoding the `EthSpec` type for `SignedBeaconBlock` as min/max values is
// same across different `EthSpec` implementations.
pub static SIGNED_BEACON_BLOCK_BASE_MIN: LazyLock<usize> = LazyLock::new(|| {
    SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Base(BeaconBlockBase::<MainnetEthSpec>::empty(
            &MainnetEthSpec::default_spec(),
        )),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len()
});
pub static SIGNED_BEACON_BLOCK_BASE_MAX: LazyLock<usize> = LazyLock::new(|| {
    SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Base(BeaconBlockBase::full(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len()
});

pub static SIGNED_BEACON_BLOCK_ALTAIR_MAX: LazyLock<usize> = LazyLock::new(|| {
    SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Altair(BeaconBlockAltair::full(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len()
});

pub static SIGNED_BEACON_BLOCK_CAPELLA_MAX_WITHOUT_PAYLOAD: LazyLock<usize> = LazyLock::new(|| {
    SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Capella(BeaconBlockCapella::full(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len()
});

pub static SIGNED_BEACON_BLOCK_ELECTRA_MAX_WITHOUT_PAYLOAD: LazyLock<usize> = LazyLock::new(|| {
    SignedBeaconBlock::<MainnetEthSpec>::from_block(
        BeaconBlock::Electra(BeaconBlockElectra::full(&MainnetEthSpec::default_spec())),
        Signature::empty(),
    )
    .as_ssz_bytes()
    .len()
});

/// The `BeaconBlockBellatrix` block has an `ExecutionPayload` field which has a max size ~16 GiB for future proofing.
/// We calculate the value from its fields instead of constructing the block and checking the length.
/// Note: This is only the theoretical upper bound. We further bound the max size we receive over the network
/// with `max_chunk_size`.
pub static SIGNED_BEACON_BLOCK_BELLATRIX_MAX: LazyLock<usize> =
    LazyLock::new(||     // Size of a full altair block
    *SIGNED_BEACON_BLOCK_ALTAIR_MAX
    + types::ExecutionPayload::<MainnetEthSpec>::max_execution_payload_bellatrix_size() // adding max size of execution payload (~16gb)
    + ssz::BYTES_PER_LENGTH_OFFSET); // Adding the additional ssz offset for the `ExecutionPayload` field

pub static SIGNED_BEACON_BLOCK_CAPELLA_MAX: LazyLock<usize> = LazyLock::new(|| {
    *SIGNED_BEACON_BLOCK_CAPELLA_MAX_WITHOUT_PAYLOAD
    + types::ExecutionPayload::<MainnetEthSpec>::max_execution_payload_capella_size() // adding max size of execution payload (~16gb)
    + ssz::BYTES_PER_LENGTH_OFFSET
}); // Adding the additional ssz offset for the `ExecutionPayload` field

pub static SIGNED_BEACON_BLOCK_DENEB_MAX: LazyLock<usize> = LazyLock::new(|| {
    *SIGNED_BEACON_BLOCK_CAPELLA_MAX_WITHOUT_PAYLOAD
    + types::ExecutionPayload::<MainnetEthSpec>::max_execution_payload_deneb_size() // adding max size of execution payload (~16gb)
    + ssz::BYTES_PER_LENGTH_OFFSET // Adding the additional offsets for the `ExecutionPayload`
    + (<types::KzgCommitment as Encode>::ssz_fixed_len() * <MainnetEthSpec>::max_blobs_per_block())
    + ssz::BYTES_PER_LENGTH_OFFSET
}); // Length offset for the blob commitments field.
    //
pub static SIGNED_BEACON_BLOCK_ELECTRA_MAX: LazyLock<usize> = LazyLock::new(|| {
    *SIGNED_BEACON_BLOCK_ELECTRA_MAX_WITHOUT_PAYLOAD
    + types::ExecutionPayload::<MainnetEthSpec>::max_execution_payload_electra_size() // adding max size of execution payload (~16gb)
    + ssz::BYTES_PER_LENGTH_OFFSET // Adding the additional ssz offset for the `ExecutionPayload` field
    + (<types::KzgCommitment as Encode>::ssz_fixed_len() * <MainnetEthSpec>::max_blobs_per_block())
    + ssz::BYTES_PER_LENGTH_OFFSET
}); // Length offset for the blob commitments field.

pub static BLOB_SIDECAR_SIZE: LazyLock<usize> =
    LazyLock::new(BlobSidecar::<MainnetEthSpec>::max_size);

pub static BLOB_SIDECAR_SIZE_MINIMAL: LazyLock<usize> =
    LazyLock::new(BlobSidecar::<MinimalEthSpec>::max_size);

pub static DATA_COLUMNS_SIDECAR_MIN: LazyLock<usize> = LazyLock::new(|| {
    DataColumnSidecar::<MainnetEthSpec>::empty()
        .as_ssz_bytes()
        .len()
});
pub static DATA_COLUMNS_SIDECAR_MAX: LazyLock<usize> =
    LazyLock::new(DataColumnSidecar::<MainnetEthSpec>::max_size);

pub static ERROR_TYPE_MIN: LazyLock<usize> = LazyLock::new(|| {
    VariableList::<u8, MaxErrorLen>::from(Vec::<u8>::new())
        .as_ssz_bytes()
        .len()
});

pub static ERROR_TYPE_MAX: LazyLock<usize> = LazyLock::new(|| {
    VariableList::<u8, MaxErrorLen>::from(vec![0u8; MAX_ERROR_LEN as usize])
        .as_ssz_bytes()
        .len()
});

pub static LIGHT_CLIENT_FINALITY_UPDATE_CAPELLA_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientFinalityUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Capella)
});
pub static LIGHT_CLIENT_FINALITY_UPDATE_DENEB_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientFinalityUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Deneb)
});
pub static LIGHT_CLIENT_FINALITY_UPDATE_ELECTRA_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientFinalityUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Electra)
});
pub static LIGHT_CLIENT_OPTIMISTIC_UPDATE_CAPELLA_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientOptimisticUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Capella)
});
pub static LIGHT_CLIENT_OPTIMISTIC_UPDATE_DENEB_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientOptimisticUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Deneb)
});
pub static LIGHT_CLIENT_OPTIMISTIC_UPDATE_ELECTRA_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientOptimisticUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Electra)
});
pub static LIGHT_CLIENT_BOOTSTRAP_CAPELLA_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientBootstrap::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Capella)
});
pub static LIGHT_CLIENT_BOOTSTRAP_DENEB_MAX: LazyLock<usize> =
    LazyLock::new(|| LightClientBootstrap::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Deneb));
pub static LIGHT_CLIENT_BOOTSTRAP_ELECTRA_MAX: LazyLock<usize> = LazyLock::new(|| {
    LightClientBootstrap::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Electra)
});

pub static LIGHT_CLIENT_UPDATES_BY_RANGE_CAPELLA_MAX: LazyLock<usize> =
    LazyLock::new(|| LightClientUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Capella));
pub static LIGHT_CLIENT_UPDATES_BY_RANGE_DENEB_MAX: LazyLock<usize> =
    LazyLock::new(|| LightClientUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Deneb));
pub static LIGHT_CLIENT_UPDATES_BY_RANGE_ELECTRA_MAX: LazyLock<usize> =
    LazyLock::new(|| LightClientUpdate::<MainnetEthSpec>::ssz_max_len_for_fork(ForkName::Electra));

/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth2/beacon_chain/req";
/// The number of seconds to wait for the first bytes of a request once a protocol has been
/// established before the stream is terminated.
const REQUEST_TIMEOUT: u64 = 15;

/// Returns the maximum bytes that can be sent across the RPC.
pub fn max_rpc_size(fork_context: &ForkContext, max_chunk_size: usize) -> usize {
    if fork_context.current_fork().bellatrix_enabled() {
        max_chunk_size
    } else {
        max_chunk_size / 10
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
        ForkName::Bellatrix => RpcLimits::new(
            *SIGNED_BEACON_BLOCK_BASE_MIN, // Base block is smaller than altair and bellatrix blocks
            *SIGNED_BEACON_BLOCK_BELLATRIX_MAX, // Bellatrix block is larger than base and altair blocks
        ),
        ForkName::Capella => RpcLimits::new(
            *SIGNED_BEACON_BLOCK_BASE_MIN, // Base block is smaller than altair and bellatrix blocks
            *SIGNED_BEACON_BLOCK_CAPELLA_MAX, // Capella block is larger than base, altair and merge blocks
        ),
        ForkName::Deneb => RpcLimits::new(
            *SIGNED_BEACON_BLOCK_BASE_MIN, // Base block is smaller than altair and bellatrix blocks
            *SIGNED_BEACON_BLOCK_DENEB_MAX, // Deneb block is larger than all prior fork blocks
        ),
        ForkName::Electra => RpcLimits::new(
            *SIGNED_BEACON_BLOCK_BASE_MIN, // Base block is smaller than altair and bellatrix blocks
            *SIGNED_BEACON_BLOCK_ELECTRA_MAX, // Electra block is larger than Deneb block
        ),
    }
}

fn rpc_light_client_updates_by_range_limits_by_fork(current_fork: ForkName) -> RpcLimits {
    let altair_fixed_len = LightClientFinalityUpdateAltair::<MainnetEthSpec>::ssz_fixed_len();

    match &current_fork {
        ForkName::Base => RpcLimits::new(0, 0),
        ForkName::Altair | ForkName::Bellatrix => {
            RpcLimits::new(altair_fixed_len, altair_fixed_len)
        }
        ForkName::Capella => {
            RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_UPDATES_BY_RANGE_CAPELLA_MAX)
        }
        ForkName::Deneb => {
            RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_UPDATES_BY_RANGE_DENEB_MAX)
        }
        ForkName::Electra => {
            RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_UPDATES_BY_RANGE_ELECTRA_MAX)
        }
    }
}

fn rpc_light_client_finality_update_limits_by_fork(current_fork: ForkName) -> RpcLimits {
    let altair_fixed_len = LightClientFinalityUpdateAltair::<MainnetEthSpec>::ssz_fixed_len();

    match &current_fork {
        ForkName::Base => RpcLimits::new(0, 0),
        ForkName::Altair | ForkName::Bellatrix => {
            RpcLimits::new(altair_fixed_len, altair_fixed_len)
        }
        ForkName::Capella => {
            RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_FINALITY_UPDATE_CAPELLA_MAX)
        }
        ForkName::Deneb => {
            RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_FINALITY_UPDATE_DENEB_MAX)
        }
        ForkName::Electra => {
            RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_FINALITY_UPDATE_ELECTRA_MAX)
        }
    }
}

fn rpc_light_client_optimistic_update_limits_by_fork(current_fork: ForkName) -> RpcLimits {
    let altair_fixed_len = LightClientOptimisticUpdateAltair::<MainnetEthSpec>::ssz_fixed_len();

    match &current_fork {
        ForkName::Base => RpcLimits::new(0, 0),
        ForkName::Altair | ForkName::Bellatrix => {
            RpcLimits::new(altair_fixed_len, altair_fixed_len)
        }
        ForkName::Capella => RpcLimits::new(
            altair_fixed_len,
            *LIGHT_CLIENT_OPTIMISTIC_UPDATE_CAPELLA_MAX,
        ),
        ForkName::Deneb => {
            RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_OPTIMISTIC_UPDATE_DENEB_MAX)
        }
        ForkName::Electra => RpcLimits::new(
            altair_fixed_len,
            *LIGHT_CLIENT_OPTIMISTIC_UPDATE_ELECTRA_MAX,
        ),
    }
}

fn rpc_light_client_bootstrap_limits_by_fork(current_fork: ForkName) -> RpcLimits {
    let altair_fixed_len = LightClientBootstrapAltair::<MainnetEthSpec>::ssz_fixed_len();

    match &current_fork {
        ForkName::Base => RpcLimits::new(0, 0),
        ForkName::Altair | ForkName::Bellatrix => {
            RpcLimits::new(altair_fixed_len, altair_fixed_len)
        }
        ForkName::Capella => RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_BOOTSTRAP_CAPELLA_MAX),
        ForkName::Deneb => RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_BOOTSTRAP_DENEB_MAX),
        ForkName::Electra => RpcLimits::new(altair_fixed_len, *LIGHT_CLIENT_BOOTSTRAP_ELECTRA_MAX),
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
    /// The `BlobsByRange` protocol name.
    #[strum(serialize = "blob_sidecars_by_range")]
    BlobsByRange,
    /// The `BlobsByRoot` protocol name.
    #[strum(serialize = "blob_sidecars_by_root")]
    BlobsByRoot,
    /// The `DataColumnSidecarsByRoot` protocol name.
    #[strum(serialize = "data_column_sidecars_by_root")]
    DataColumnsByRoot,
    /// The `DataColumnSidecarsByRange` protocol name.
    #[strum(serialize = "data_column_sidecars_by_range")]
    DataColumnsByRange,
    /// The `Ping` protocol name.
    Ping,
    /// The `MetaData` protocol name.
    #[strum(serialize = "metadata")]
    MetaData,
    /// The `LightClientBootstrap` protocol name.
    #[strum(serialize = "light_client_bootstrap")]
    LightClientBootstrap,
    /// The `LightClientOptimisticUpdate` protocol name.
    #[strum(serialize = "light_client_optimistic_update")]
    LightClientOptimisticUpdate,
    /// The `LightClientFinalityUpdate` protocol name.
    #[strum(serialize = "light_client_finality_update")]
    LightClientFinalityUpdate,
    /// The `LightClientUpdatesByRange` protocol name
    #[strum(serialize = "light_client_updates_by_range")]
    LightClientUpdatesByRange,
}

impl Protocol {
    pub(crate) fn terminator(self) -> Option<ResponseTermination> {
        match self {
            Protocol::Status => None,
            Protocol::Goodbye => None,
            Protocol::BlocksByRange => Some(ResponseTermination::BlocksByRange),
            Protocol::BlocksByRoot => Some(ResponseTermination::BlocksByRoot),
            Protocol::BlobsByRange => Some(ResponseTermination::BlobsByRange),
            Protocol::BlobsByRoot => Some(ResponseTermination::BlobsByRoot),
            Protocol::DataColumnsByRoot => Some(ResponseTermination::DataColumnsByRoot),
            Protocol::DataColumnsByRange => Some(ResponseTermination::DataColumnsByRange),
            Protocol::Ping => None,
            Protocol::MetaData => None,
            Protocol::LightClientBootstrap => None,
            Protocol::LightClientOptimisticUpdate => None,
            Protocol::LightClientFinalityUpdate => None,
            Protocol::LightClientUpdatesByRange => None,
        }
    }
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
    BlobsByRangeV1,
    BlobsByRootV1,
    DataColumnsByRootV1,
    DataColumnsByRangeV1,
    PingV1,
    MetaDataV1,
    MetaDataV2,
    MetaDataV3,
    LightClientBootstrapV1,
    LightClientOptimisticUpdateV1,
    LightClientFinalityUpdateV1,
    LightClientUpdatesByRangeV1,
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
            SupportedProtocol::BlobsByRangeV1 => "1",
            SupportedProtocol::BlobsByRootV1 => "1",
            SupportedProtocol::DataColumnsByRootV1 => "1",
            SupportedProtocol::DataColumnsByRangeV1 => "1",
            SupportedProtocol::PingV1 => "1",
            SupportedProtocol::MetaDataV1 => "1",
            SupportedProtocol::MetaDataV2 => "2",
            SupportedProtocol::MetaDataV3 => "3",
            SupportedProtocol::LightClientBootstrapV1 => "1",
            SupportedProtocol::LightClientOptimisticUpdateV1 => "1",
            SupportedProtocol::LightClientFinalityUpdateV1 => "1",
            SupportedProtocol::LightClientUpdatesByRangeV1 => "1",
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
            SupportedProtocol::BlobsByRangeV1 => Protocol::BlobsByRange,
            SupportedProtocol::BlobsByRootV1 => Protocol::BlobsByRoot,
            SupportedProtocol::DataColumnsByRootV1 => Protocol::DataColumnsByRoot,
            SupportedProtocol::DataColumnsByRangeV1 => Protocol::DataColumnsByRange,
            SupportedProtocol::PingV1 => Protocol::Ping,
            SupportedProtocol::MetaDataV1 => Protocol::MetaData,
            SupportedProtocol::MetaDataV2 => Protocol::MetaData,
            SupportedProtocol::MetaDataV3 => Protocol::MetaData,
            SupportedProtocol::LightClientBootstrapV1 => Protocol::LightClientBootstrap,
            SupportedProtocol::LightClientOptimisticUpdateV1 => {
                Protocol::LightClientOptimisticUpdate
            }
            SupportedProtocol::LightClientFinalityUpdateV1 => Protocol::LightClientFinalityUpdate,
            SupportedProtocol::LightClientUpdatesByRangeV1 => Protocol::LightClientUpdatesByRange,
        }
    }

    fn currently_supported(fork_context: &ForkContext) -> Vec<ProtocolId> {
        let mut supported = vec![
            ProtocolId::new(Self::StatusV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::GoodbyeV1, Encoding::SSZSnappy),
            // V2 variants have higher preference then V1
            ProtocolId::new(Self::BlocksByRangeV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRangeV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::PingV1, Encoding::SSZSnappy),
        ];
        if fork_context.spec.is_peer_das_scheduled() {
            supported.extend_from_slice(&[
                // V3 variants have higher preference for protocol negotation
                ProtocolId::new(Self::MetaDataV3, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV1, Encoding::SSZSnappy),
            ]);
        } else {
            supported.extend_from_slice(&[
                ProtocolId::new(Self::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV1, Encoding::SSZSnappy),
            ]);
        }
        if fork_context.fork_exists(ForkName::Deneb) {
            supported.extend_from_slice(&[
                ProtocolId::new(SupportedProtocol::BlobsByRootV1, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlobsByRangeV1, Encoding::SSZSnappy),
            ]);
        }
        if fork_context.spec.is_peer_das_scheduled() {
            supported.extend_from_slice(&[
                ProtocolId::new(SupportedProtocol::DataColumnsByRootV1, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::DataColumnsByRangeV1, Encoding::SSZSnappy),
            ]);
        }
        supported
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
pub struct RPCProtocol<E: EthSpec> {
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
    pub enable_light_client_server: bool,
    pub phantom: PhantomData<E>,
    pub ttfb_timeout: Duration,
}

impl<E: EthSpec> UpgradeInfo for RPCProtocol<E> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    /// The list of supported RPC protocols for Lighthouse.
    fn protocol_info(&self) -> Self::InfoIter {
        let mut supported_protocols = SupportedProtocol::currently_supported(&self.fork_context);
        if self.enable_light_client_server {
            supported_protocols.push(ProtocolId::new(
                SupportedProtocol::LightClientBootstrapV1,
                Encoding::SSZSnappy,
            ));
            supported_protocols.push(ProtocolId::new(
                SupportedProtocol::LightClientOptimisticUpdateV1,
                Encoding::SSZSnappy,
            ));
            supported_protocols.push(ProtocolId::new(
                SupportedProtocol::LightClientFinalityUpdateV1,
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
    pub fn rpc_request_limits(&self, spec: &ChainSpec) -> RpcLimits {
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
            Protocol::BlocksByRoot => RpcLimits::new(0, spec.max_blocks_by_root_request),
            Protocol::BlobsByRange => RpcLimits::new(
                <BlobsByRangeRequest as Encode>::ssz_fixed_len(),
                <BlobsByRangeRequest as Encode>::ssz_fixed_len(),
            ),
            Protocol::BlobsByRoot => RpcLimits::new(0, spec.max_blobs_by_root_request),
            Protocol::DataColumnsByRoot => RpcLimits::new(0, spec.max_data_columns_by_root_request),
            Protocol::DataColumnsByRange => RpcLimits::new(
                DataColumnsByRangeRequest::ssz_min_len(),
                DataColumnsByRangeRequest::ssz_max_len(spec),
            ),
            Protocol::Ping => RpcLimits::new(
                <Ping as Encode>::ssz_fixed_len(),
                <Ping as Encode>::ssz_fixed_len(),
            ),
            Protocol::LightClientBootstrap => RpcLimits::new(
                <LightClientBootstrapRequest as Encode>::ssz_fixed_len(),
                <LightClientBootstrapRequest as Encode>::ssz_fixed_len(),
            ),
            Protocol::LightClientOptimisticUpdate => RpcLimits::new(0, 0),
            Protocol::LightClientFinalityUpdate => RpcLimits::new(0, 0),
            Protocol::LightClientUpdatesByRange => RpcLimits::new(
                LightClientUpdatesByRangeRequest::ssz_min_len(),
                LightClientUpdatesByRangeRequest::ssz_max_len(),
            ),
            Protocol::MetaData => RpcLimits::new(0, 0), // Metadata requests are empty
        }
    }

    /// Returns min and max size for messages of given protocol id responses.
    pub fn rpc_response_limits<E: EthSpec>(&self, fork_context: &ForkContext) -> RpcLimits {
        match self.versioned_protocol.protocol() {
            Protocol::Status => RpcLimits::new(
                <StatusMessage as Encode>::ssz_fixed_len(),
                <StatusMessage as Encode>::ssz_fixed_len(),
            ),
            Protocol::Goodbye => RpcLimits::new(0, 0), // Goodbye request has no response
            Protocol::BlocksByRange => rpc_block_limits_by_fork(fork_context.current_fork()),
            Protocol::BlocksByRoot => rpc_block_limits_by_fork(fork_context.current_fork()),
            Protocol::BlobsByRange => rpc_blob_limits::<E>(),
            Protocol::BlobsByRoot => rpc_blob_limits::<E>(),
            Protocol::DataColumnsByRoot => rpc_data_column_limits(),
            Protocol::DataColumnsByRange => rpc_data_column_limits(),
            Protocol::Ping => RpcLimits::new(
                <Ping as Encode>::ssz_fixed_len(),
                <Ping as Encode>::ssz_fixed_len(),
            ),
            Protocol::MetaData => RpcLimits::new(
                <MetaDataV1<E> as Encode>::ssz_fixed_len(),
                <MetaDataV3<E> as Encode>::ssz_fixed_len(),
            ),
            Protocol::LightClientBootstrap => {
                rpc_light_client_bootstrap_limits_by_fork(fork_context.current_fork())
            }
            Protocol::LightClientOptimisticUpdate => {
                rpc_light_client_optimistic_update_limits_by_fork(fork_context.current_fork())
            }
            Protocol::LightClientFinalityUpdate => {
                rpc_light_client_finality_update_limits_by_fork(fork_context.current_fork())
            }
            Protocol::LightClientUpdatesByRange => {
                rpc_light_client_updates_by_range_limits_by_fork(fork_context.current_fork())
            }
        }
    }

    /// Returns `true` if the given `ProtocolId` should expect `context_bytes` in the
    /// beginning of the stream, else returns `false`.
    pub fn has_context_bytes(&self) -> bool {
        match self.versioned_protocol {
            SupportedProtocol::BlocksByRangeV2
            | SupportedProtocol::BlocksByRootV2
            | SupportedProtocol::BlobsByRangeV1
            | SupportedProtocol::BlobsByRootV1
            | SupportedProtocol::DataColumnsByRootV1
            | SupportedProtocol::DataColumnsByRangeV1
            | SupportedProtocol::LightClientBootstrapV1
            | SupportedProtocol::LightClientOptimisticUpdateV1
            | SupportedProtocol::LightClientFinalityUpdateV1
            | SupportedProtocol::LightClientUpdatesByRangeV1 => true,
            SupportedProtocol::StatusV1
            | SupportedProtocol::BlocksByRootV1
            | SupportedProtocol::BlocksByRangeV1
            | SupportedProtocol::PingV1
            | SupportedProtocol::MetaDataV1
            | SupportedProtocol::MetaDataV2
            | SupportedProtocol::MetaDataV3
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

pub fn rpc_blob_limits<E: EthSpec>() -> RpcLimits {
    match E::spec_name() {
        EthSpecId::Minimal => {
            RpcLimits::new(*BLOB_SIDECAR_SIZE_MINIMAL, *BLOB_SIDECAR_SIZE_MINIMAL)
        }
        EthSpecId::Mainnet | EthSpecId::Gnosis => {
            RpcLimits::new(*BLOB_SIDECAR_SIZE, *BLOB_SIDECAR_SIZE)
        }
    }
}

pub fn rpc_data_column_limits() -> RpcLimits {
    RpcLimits::new(*DATA_COLUMNS_SIDECAR_MIN, *DATA_COLUMNS_SIDECAR_MAX)
}

/* Inbound upgrade */

// The inbound protocol reads the request, decodes it and returns the stream to the protocol
// handler to respond to once ready.

pub type InboundOutput<TSocket, E> = (RequestType<E>, InboundFramed<TSocket, E>);
pub type InboundFramed<TSocket, E> =
    Framed<std::pin::Pin<Box<TimeoutStream<Compat<TSocket>>>>, SSZSnappyInboundCodec<E>>;

impl<TSocket, E> InboundUpgrade<TSocket> for RPCProtocol<E>
where
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: EthSpec,
{
    type Output = InboundOutput<TSocket, E>;
    type Error = RPCError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: TSocket, protocol: ProtocolId) -> Self::Future {
        async move {
            let versioned_protocol = protocol.versioned_protocol;
            // convert the socket to tokio compatible socket
            let socket = socket.compat();
            let codec = match protocol.encoding {
                Encoding::SSZSnappy => SSZSnappyInboundCodec::new(
                    protocol,
                    self.max_rpc_size,
                    self.fork_context.clone(),
                ),
            };

            let mut timed_socket = TimeoutStream::new(socket);
            timed_socket.set_read_timeout(Some(self.ttfb_timeout));

            let socket = Framed::new(Box::pin(timed_socket), codec);

            // MetaData requests should be empty, return the stream
            match versioned_protocol {
                SupportedProtocol::MetaDataV1 => {
                    Ok((RequestType::MetaData(MetadataRequest::new_v1()), socket))
                }
                SupportedProtocol::MetaDataV2 => {
                    Ok((RequestType::MetaData(MetadataRequest::new_v2()), socket))
                }
                SupportedProtocol::MetaDataV3 => {
                    Ok((RequestType::MetaData(MetadataRequest::new_v3()), socket))
                }
                SupportedProtocol::LightClientOptimisticUpdateV1 => {
                    Ok((RequestType::LightClientOptimisticUpdate, socket))
                }
                SupportedProtocol::LightClientFinalityUpdateV1 => {
                    Ok((RequestType::LightClientFinalityUpdate, socket))
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
pub enum RequestType<E: EthSpec> {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    BlocksByRange(OldBlocksByRangeRequest),
    BlocksByRoot(BlocksByRootRequest),
    BlobsByRange(BlobsByRangeRequest),
    BlobsByRoot(BlobsByRootRequest),
    DataColumnsByRoot(DataColumnsByRootRequest),
    DataColumnsByRange(DataColumnsByRangeRequest),
    LightClientBootstrap(LightClientBootstrapRequest),
    LightClientOptimisticUpdate,
    LightClientFinalityUpdate,
    LightClientUpdatesByRange(LightClientUpdatesByRangeRequest),
    Ping(Ping),
    MetaData(MetadataRequest<E>),
}

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<E: EthSpec> RequestType<E> {
    /* These functions are used in the handler for stream management */

    /// Maximum number of responses expected for this request.
    pub fn max_responses(&self) -> u64 {
        match self {
            RequestType::Status(_) => 1,
            RequestType::Goodbye(_) => 0,
            RequestType::BlocksByRange(req) => *req.count(),
            RequestType::BlocksByRoot(req) => req.block_roots().len() as u64,
            RequestType::BlobsByRange(req) => req.max_blobs_requested::<E>(),
            RequestType::BlobsByRoot(req) => req.blob_ids.len() as u64,
            RequestType::DataColumnsByRoot(req) => req.data_column_ids.len() as u64,
            RequestType::DataColumnsByRange(req) => req.max_requested::<E>(),
            RequestType::Ping(_) => 1,
            RequestType::MetaData(_) => 1,
            RequestType::LightClientBootstrap(_) => 1,
            RequestType::LightClientOptimisticUpdate => 1,
            RequestType::LightClientFinalityUpdate => 1,
            RequestType::LightClientUpdatesByRange(req) => req.count,
        }
    }

    /// Gives the corresponding `SupportedProtocol` to this request.
    pub fn versioned_protocol(&self) -> SupportedProtocol {
        match self {
            RequestType::Status(_) => SupportedProtocol::StatusV1,
            RequestType::Goodbye(_) => SupportedProtocol::GoodbyeV1,
            RequestType::BlocksByRange(req) => match req {
                OldBlocksByRangeRequest::V1(_) => SupportedProtocol::BlocksByRangeV1,
                OldBlocksByRangeRequest::V2(_) => SupportedProtocol::BlocksByRangeV2,
            },
            RequestType::BlocksByRoot(req) => match req {
                BlocksByRootRequest::V1(_) => SupportedProtocol::BlocksByRootV1,
                BlocksByRootRequest::V2(_) => SupportedProtocol::BlocksByRootV2,
            },
            RequestType::BlobsByRange(_) => SupportedProtocol::BlobsByRangeV1,
            RequestType::BlobsByRoot(_) => SupportedProtocol::BlobsByRootV1,
            RequestType::DataColumnsByRoot(_) => SupportedProtocol::DataColumnsByRootV1,
            RequestType::DataColumnsByRange(_) => SupportedProtocol::DataColumnsByRangeV1,
            RequestType::Ping(_) => SupportedProtocol::PingV1,
            RequestType::MetaData(req) => match req {
                MetadataRequest::V1(_) => SupportedProtocol::MetaDataV1,
                MetadataRequest::V2(_) => SupportedProtocol::MetaDataV2,
                MetadataRequest::V3(_) => SupportedProtocol::MetaDataV3,
            },
            RequestType::LightClientBootstrap(_) => SupportedProtocol::LightClientBootstrapV1,
            RequestType::LightClientOptimisticUpdate => {
                SupportedProtocol::LightClientOptimisticUpdateV1
            }
            RequestType::LightClientFinalityUpdate => {
                SupportedProtocol::LightClientFinalityUpdateV1
            }
            RequestType::LightClientUpdatesByRange(_) => {
                SupportedProtocol::LightClientUpdatesByRangeV1
            }
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            RequestType::BlocksByRange(_) => ResponseTermination::BlocksByRange,
            RequestType::BlocksByRoot(_) => ResponseTermination::BlocksByRoot,
            RequestType::BlobsByRange(_) => ResponseTermination::BlobsByRange,
            RequestType::BlobsByRoot(_) => ResponseTermination::BlobsByRoot,
            RequestType::DataColumnsByRoot(_) => ResponseTermination::DataColumnsByRoot,
            RequestType::DataColumnsByRange(_) => ResponseTermination::DataColumnsByRange,
            RequestType::Status(_) => unreachable!(),
            RequestType::Goodbye(_) => unreachable!(),
            RequestType::Ping(_) => unreachable!(),
            RequestType::MetaData(_) => unreachable!(),
            RequestType::LightClientBootstrap(_) => unreachable!(),
            RequestType::LightClientFinalityUpdate => unreachable!(),
            RequestType::LightClientOptimisticUpdate => unreachable!(),
            RequestType::LightClientUpdatesByRange(_) => unreachable!(),
        }
    }

    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            RequestType::Status(_) => vec![ProtocolId::new(
                SupportedProtocol::StatusV1,
                Encoding::SSZSnappy,
            )],
            RequestType::Goodbye(_) => vec![ProtocolId::new(
                SupportedProtocol::GoodbyeV1,
                Encoding::SSZSnappy,
            )],
            RequestType::BlocksByRange(_) => vec![
                ProtocolId::new(SupportedProtocol::BlocksByRangeV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlocksByRangeV1, Encoding::SSZSnappy),
            ],
            RequestType::BlocksByRoot(_) => vec![
                ProtocolId::new(SupportedProtocol::BlocksByRootV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlocksByRootV1, Encoding::SSZSnappy),
            ],
            RequestType::BlobsByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::BlobsByRangeV1,
                Encoding::SSZSnappy,
            )],
            RequestType::BlobsByRoot(_) => vec![ProtocolId::new(
                SupportedProtocol::BlobsByRootV1,
                Encoding::SSZSnappy,
            )],
            RequestType::DataColumnsByRoot(_) => vec![ProtocolId::new(
                SupportedProtocol::DataColumnsByRootV1,
                Encoding::SSZSnappy,
            )],
            RequestType::DataColumnsByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::DataColumnsByRangeV1,
                Encoding::SSZSnappy,
            )],
            RequestType::Ping(_) => vec![ProtocolId::new(
                SupportedProtocol::PingV1,
                Encoding::SSZSnappy,
            )],
            RequestType::MetaData(_) => vec![
                ProtocolId::new(SupportedProtocol::MetaDataV3, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::MetaDataV1, Encoding::SSZSnappy),
            ],
            RequestType::LightClientBootstrap(_) => vec![ProtocolId::new(
                SupportedProtocol::LightClientBootstrapV1,
                Encoding::SSZSnappy,
            )],
            RequestType::LightClientOptimisticUpdate => vec![ProtocolId::new(
                SupportedProtocol::LightClientOptimisticUpdateV1,
                Encoding::SSZSnappy,
            )],
            RequestType::LightClientFinalityUpdate => vec![ProtocolId::new(
                SupportedProtocol::LightClientFinalityUpdateV1,
                Encoding::SSZSnappy,
            )],
            RequestType::LightClientUpdatesByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::LightClientUpdatesByRangeV1,
                Encoding::SSZSnappy,
            )],
        }
    }

    pub fn expect_exactly_one_response(&self) -> bool {
        match self {
            RequestType::Status(_) => true,
            RequestType::Goodbye(_) => false,
            RequestType::BlocksByRange(_) => false,
            RequestType::BlocksByRoot(_) => false,
            RequestType::BlobsByRange(_) => false,
            RequestType::BlobsByRoot(_) => false,
            RequestType::DataColumnsByRoot(_) => false,
            RequestType::DataColumnsByRange(_) => false,
            RequestType::Ping(_) => true,
            RequestType::MetaData(_) => true,
            RequestType::LightClientBootstrap(_) => true,
            RequestType::LightClientOptimisticUpdate => true,
            RequestType::LightClientFinalityUpdate => true,
            RequestType::LightClientUpdatesByRange(_) => true,
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
    ErrorResponse(RpcErrorResponse, String),
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

impl<E: EthSpec> std::fmt::Display for RequestType<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestType::Status(status) => write!(f, "Status Message: {}", status),
            RequestType::Goodbye(reason) => write!(f, "Goodbye: {}", reason),
            RequestType::BlocksByRange(req) => write!(f, "Blocks by range: {}", req),
            RequestType::BlocksByRoot(req) => write!(f, "Blocks by root: {:?}", req),
            RequestType::BlobsByRange(req) => write!(f, "Blobs by range: {:?}", req),
            RequestType::BlobsByRoot(req) => write!(f, "Blobs by root: {:?}", req),
            RequestType::DataColumnsByRoot(req) => write!(f, "Data columns by root: {:?}", req),
            RequestType::DataColumnsByRange(req) => {
                write!(f, "Data columns by range: {:?}", req)
            }
            RequestType::Ping(ping) => write!(f, "Ping: {}", ping.data),
            RequestType::MetaData(_) => write!(f, "MetaData request"),
            RequestType::LightClientBootstrap(bootstrap) => {
                write!(f, "Light client boostrap: {}", bootstrap.root)
            }
            RequestType::LightClientOptimisticUpdate => {
                write!(f, "Light client optimistic update request")
            }
            RequestType::LightClientFinalityUpdate => {
                write!(f, "Light client finality update request")
            }
            RequestType::LightClientUpdatesByRange(_) => {
                write!(f, "Light client updates by range request")
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
