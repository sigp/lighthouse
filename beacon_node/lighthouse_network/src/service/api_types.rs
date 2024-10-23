use std::sync::Arc;

use libp2p::swarm::ConnectionId;
use strum::IntoStaticStr;
use types::{
    BlobSidecar, DataColumnSidecar, EthSpec, Hash256, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, LightClientUpdate, SignedBeaconBlock,
};

use crate::rpc::{
    methods::{ResponseTermination, RpcResponse, RpcSuccessResponse, StatusMessage},
    SubstreamId,
};

/// Identifier of requests sent by a peer.
pub type PeerRequestId = (ConnectionId, SubstreamId);

pub type Id = u32;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SingleLookupReqId {
    pub lookup_id: Id,
    pub req_id: Id,
}

/// Id of rpc requests sent by sync to the network.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum SyncRequestId {
    /// Request searching for a block given a hash.
    SingleBlock { id: SingleLookupReqId },
    /// Request searching for a set of blobs given a hash.
    SingleBlob { id: SingleLookupReqId },
    /// Request searching for a set of data columns given a hash and list of column indices.
    DataColumnsByRoot(DataColumnsByRootRequestId),
    /// Range request that is composed by both a block range request and a blob range request.
    RangeBlockAndBlobs { id: Id },
}

/// Request ID for data_columns_by_root requests. Block lookups do not issue this request directly.
/// Wrapping this particular req_id, ensures not mixing this request with a custody req_id.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct DataColumnsByRootRequestId {
    pub id: Id,
    pub requester: DataColumnsByRootRequester,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum DataColumnsByRootRequester {
    Sampling(SamplingId),
    Custody(CustodyId),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SamplingId {
    pub id: SamplingRequester,
    pub sampling_request_id: SamplingRequestId,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum SamplingRequester {
    ImportedBlock(Hash256),
}

/// Identifier of sampling requests.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SamplingRequestId(pub usize);

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct CustodyId {
    pub requester: CustodyRequester,
    pub req_id: Id,
}

/// Downstream components that perform custody by root requests.
/// Currently, it's only single block lookups, so not using an enum
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct CustodyRequester(pub SingleLookupReqId);

/// Application level requests sent to the network.
#[derive(Debug, Clone, Copy)]
pub enum AppRequestId {
    Sync(SyncRequestId),
    Router,
}

/// Global identifier of a request.
#[derive(Debug, Clone, Copy)]
pub enum RequestId {
    Application(AppRequestId),
    Internal,
}

/// The type of RPC requests the Behaviour informs it has received and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level requests that can be
//       sent. The main difference is the absence of the Ping, Metadata and Goodbye protocols, which don't
//       leave the Behaviour. For all protocols managed by RPC see `RPCRequest`.
#[derive(Debug, Clone, PartialEq, IntoStaticStr)]
pub enum Request {
    /// A Status message.
    Status(StatusMessage),
    /// A blocks by range request.
    BlocksByRange(BlocksByRangeRequest),
    /// A blobs by range request.
    BlobsByRange(BlobsByRangeRequest),
    /// A request blocks root request.
    BlocksByRoot(BlocksByRootRequest),
    // light client bootstrap request
    LightClientBootstrap(LightClientBootstrapRequest),
    // light client optimistic update request
    LightClientOptimisticUpdate,
    // light client finality update request
    LightClientFinalityUpdate,
    /// A request blobs root request.
    BlobsByRoot(BlobsByRootRequest),
    /// A request data columns root request.
    DataColumnsByRoot(DataColumnsByRootRequest),
    /// A request data columns by range request.
    DataColumnsByRange(DataColumnsByRangeRequest),
}

impl<E: EthSpec> std::convert::From<Request> for OutboundRequest<E> {
    fn from(req: Request) -> OutboundRequest<E> {
        match req {
            Request::BlocksByRoot(r) => OutboundRequest::BlocksByRoot(r),
            Request::BlocksByRange(r) => match r {
                BlocksByRangeRequest::V1(req) => OutboundRequest::BlocksByRange(
                    OldBlocksByRangeRequest::V1(OldBlocksByRangeRequestV1 {
                        start_slot: req.start_slot,
                        count: req.count,
                        step: 1,
                    }),
                ),
                BlocksByRangeRequest::V2(req) => OutboundRequest::BlocksByRange(
                    OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2 {
                        start_slot: req.start_slot,
                        count: req.count,
                        step: 1,
                    }),
                ),
            },
            Request::LightClientBootstrap(_)
            | Request::LightClientOptimisticUpdate
            | Request::LightClientFinalityUpdate => {
                unreachable!("Lighthouse never makes an outbound light client request")
            }
            Request::BlobsByRange(r) => OutboundRequest::BlobsByRange(r),
            Request::BlobsByRoot(r) => OutboundRequest::BlobsByRoot(r),
            Request::DataColumnsByRoot(r) => OutboundRequest::DataColumnsByRoot(r),
            Request::DataColumnsByRange(r) => OutboundRequest::DataColumnsByRange(r),
            Request::Status(s) => OutboundRequest::Status(s),
        }
    }
}

/// The type of RPC responses the Behaviour informs it has received, and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level responses that can be
//       sent. The main difference is the absense of Pong and Metadata, which don't leave the
//       Behaviour. For all protocol reponses managed by RPC see `RPCResponse` and
//       `RPCCodedResponse`.
#[derive(Debug, Clone, PartialEq, IntoStaticStr)]
pub enum Response<E: EthSpec> {
    /// A Status message.
    Status(StatusMessage),
    /// A response to a get BLOCKS_BY_RANGE request. A None response signals the end of the batch.
    BlocksByRange(Option<Arc<SignedBeaconBlock<E>>>),
    /// A response to a get BLOBS_BY_RANGE request. A None response signals the end of the batch.
    BlobsByRange(Option<Arc<BlobSidecar<E>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_Range request.
    DataColumnsByRange(Option<Arc<DataColumnSidecar<E>>>),
    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Option<Arc<SignedBeaconBlock<E>>>),
    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Option<Arc<BlobSidecar<E>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_ROOT request.
    DataColumnsByRoot(Option<Arc<DataColumnSidecar<E>>>),
    /// A response to a LightClientUpdate request.
    LightClientBootstrap(Arc<LightClientBootstrap<E>>),
    /// A response to a LightClientOptimisticUpdate request.
    LightClientOptimisticUpdate(Arc<LightClientOptimisticUpdate<E>>),
    /// A response to a LightClientFinalityUpdate request.
    LightClientFinalityUpdate(Arc<LightClientFinalityUpdate<E>>),
    /// A response to a LightClientUpdatesByRange request.
    LightClientUpdatesByRange(Option<Arc<LightClientUpdate<E>>>),
}

impl<E: EthSpec> std::convert::From<Response<E>> for RpcResponse<E> {
    fn from(resp: Response<E>) -> RpcResponse<E> {
        match resp {
            Response::BlocksByRoot(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlocksByRoot),
            },
            Response::BlocksByRange(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlocksByRange(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlocksByRange),
            },
            Response::BlobsByRoot(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlobsByRoot(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlobsByRoot),
            },
            Response::BlobsByRange(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlobsByRange(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlobsByRange),
            },
            Response::DataColumnsByRoot(r) => match r {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::DataColumnsByRoot(d)),
                None => RpcResponse::StreamTermination(ResponseTermination::DataColumnsByRoot),
            },
            Response::DataColumnsByRange(r) => match r {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::DataColumnsByRange(d)),
                None => RpcResponse::StreamTermination(ResponseTermination::DataColumnsByRange),
            },
            Response::Status(s) => RpcResponse::Success(RpcSuccessResponse::Status(s)),
            Response::LightClientBootstrap(b) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientBootstrap(b))
            }
            Response::LightClientOptimisticUpdate(o) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientOptimisticUpdate(o))
            }
            Response::LightClientFinalityUpdate(f) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientFinalityUpdate(f))
            }
            Response::LightClientUpdatesByRange(f) => match f {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::LightClientUpdatesByRange(d)),
                None => {
                    RpcResponse::StreamTermination(ResponseTermination::LightClientUpdatesByRange)
                }
            },
        }
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
            RequestId::Internal => slog::Value::serialize("Behaviour", record, key, serializer),
            RequestId::Application(ref id) => {
                slog::Value::serialize(&format_args!("{:?}", id), record, key, serializer)
            }
        }
    }
}

// This custom impl reduces log boilerplate not printing `DataColumnsByRootRequestId` on each id log
impl std::fmt::Display for DataColumnsByRootRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {:?}", self.id, self.requester)
    }
}
