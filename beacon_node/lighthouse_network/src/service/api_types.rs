use std::sync::Arc;

use libp2p::swarm::ConnectionId;
use types::{BlobSidecar, DataColumnSidecar, EthSpec, LightClientBootstrap, SignedBeaconBlock};

use crate::rpc::methods::{BlobsByRangeRequest, BlobsByRootRequest, DataColumnsByRootRequest};
use crate::rpc::{
    methods::{
        BlocksByRangeRequest, BlocksByRootRequest, LightClientBootstrapRequest,
        OldBlocksByRangeRequest, OldBlocksByRangeRequestV1, OldBlocksByRangeRequestV2,
        RPCCodedResponse, RPCResponse, ResponseTermination, StatusMessage,
    },
    OutboundRequest, SubstreamId,
};

use super::methods::DataColumnsByRangeRequest;

/// Identifier of requests sent by a peer.
pub type PeerRequestId = (ConnectionId, SubstreamId);

/// Identifier of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestId<AppReqId> {
    Application(AppReqId),
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
    /// A request blobs root request.
    BlobsByRoot(BlobsByRootRequest),
    /// A request data columns root request.
    DataColumnsByRoot(DataColumnsByRootRequest),
    /// A blobs by range request.
    DataColumnsByRange(DataColumnsByRangeRequest),
}

impl<TSpec: EthSpec> std::convert::From<Request> for OutboundRequest<TSpec> {
    fn from(req: Request) -> OutboundRequest<TSpec> {
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
            Request::LightClientBootstrap(_) => {
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
#[derive(Debug, Clone, PartialEq)]
pub enum Response<TSpec: EthSpec> {
    /// A Status message.
    Status(StatusMessage),
    /// A response to a get BLOCKS_BY_RANGE request. A None response signals the end of the batch.
    BlocksByRange(Option<Arc<SignedBeaconBlock<TSpec>>>),
    /// A response to a get BLOBS_BY_RANGE request. A None response signals the end of the batch.
    BlobsByRange(Option<Arc<BlobSidecar<TSpec>>>),
    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Option<Arc<SignedBeaconBlock<TSpec>>>),
    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Option<Arc<BlobSidecar<TSpec>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_ROOT request.
    DataColumnsByRoot(Option<Arc<DataColumnSidecar<TSpec>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_RANGE request. A None response signals the end of the batch.
    DataColumnsByRange(Option<Arc<DataColumnSidecar<TSpec>>>),
    /// A response to a LightClientUpdate request.
    LightClientBootstrap(LightClientBootstrap<TSpec>),
}

impl<TSpec: EthSpec> std::convert::From<Response<TSpec>> for RPCCodedResponse<TSpec> {
    fn from(resp: Response<TSpec>) -> RPCCodedResponse<TSpec> {
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
            Response::DataColumnsByRoot(r) => match r {
                Some(d) => RPCCodedResponse::Success(RPCResponse::DataColumnsByRoot(d)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::DataColumnsByRoot),
            },
            Response::DataColumnsByRange(r) => match r {
                Some(d) => RPCCodedResponse::Success(RPCResponse::DataColumnsByRange(d)),
                None => {
                    RPCCodedResponse::StreamTermination(ResponseTermination::DataColumnsByRange)
                }
            },
            Response::Status(s) => RPCCodedResponse::Success(RPCResponse::Status(s)),
            Response::LightClientBootstrap(b) => {
                RPCCodedResponse::Success(RPCResponse::LightClientBootstrap(b))
            }
        }
    }
}

impl<AppReqId: std::fmt::Debug> slog::Value for RequestId<AppReqId> {
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
