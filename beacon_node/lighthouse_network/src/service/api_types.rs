use std::sync::Arc;

use libp2p::swarm::ConnectionId;
use types::{
    BlobSidecar, EthSpec, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientOptimisticUpdate, SignedBeaconBlock,
};

use crate::rpc::methods::{BlobsByRangeRequest, BlobsByRootRequest};
use crate::rpc::{
    methods::{
        BlocksByRangeRequest, BlocksByRootRequest, LightClientBootstrapRequest,
        OldBlocksByRangeRequest, OldBlocksByRangeRequestV1, OldBlocksByRangeRequestV2,
        RPCCodedResponse, RPCResponse, ResponseTermination, StatusMessage,
    },
    OutboundRequest, SubstreamId,
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
    /// Range request that is composed by both a block range request and a blob range request.
    RangeBlockAndBlobs { id: Id },
}

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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub enum Response<E: EthSpec> {
    /// A Status message.
    Status(StatusMessage),
    /// A response to a get BLOCKS_BY_RANGE request. A None response signals the end of the batch.
    BlocksByRange(Option<Arc<SignedBeaconBlock<E>>>),
    /// A response to a get BLOBS_BY_RANGE request. A None response signals the end of the batch.
    BlobsByRange(Option<Arc<BlobSidecar<E>>>),
    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Option<Arc<SignedBeaconBlock<E>>>),
    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Option<Arc<BlobSidecar<E>>>),
    /// A response to a LightClientUpdate request.
    LightClientBootstrap(Arc<LightClientBootstrap<E>>),
    /// A response to a LightClientOptimisticUpdate request.
    LightClientOptimisticUpdate(Arc<LightClientOptimisticUpdate<E>>),
    /// A response to a LightClientFinalityUpdate request.
    LightClientFinalityUpdate(Arc<LightClientFinalityUpdate<E>>),
}

impl<E: EthSpec> std::convert::From<Response<E>> for RPCCodedResponse<E> {
    fn from(resp: Response<E>) -> RPCCodedResponse<E> {
        match resp {
            Response::BlocksByRoot(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::BlocksByRoot(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::BlocksByRoot),
            },
            Response::BlocksByRange(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::BlocksByRange(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::BlocksByRange),
            },
            Response::BlobsByRoot(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::BlobsByRoot(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::BlobsByRoot),
            },
            Response::BlobsByRange(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::BlobsByRange(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::BlobsByRange),
            },
            Response::Status(s) => RPCCodedResponse::Success(RPCResponse::Status(s)),
            Response::LightClientBootstrap(b) => {
                RPCCodedResponse::Success(RPCResponse::LightClientBootstrap(b))
            }
            Response::LightClientOptimisticUpdate(o) => {
                RPCCodedResponse::Success(RPCResponse::LightClientOptimisticUpdate(o))
            }
            Response::LightClientFinalityUpdate(f) => {
                RPCCodedResponse::Success(RPCResponse::LightClientFinalityUpdate(f))
            }
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
