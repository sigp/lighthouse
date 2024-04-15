use super::methods::*;
use super::protocol::ProtocolId;
use super::protocol::SupportedProtocol;
use super::RPCError;
use crate::rpc::codec::{
    base::BaseOutboundCodec, ssz_snappy::SSZSnappyOutboundCodec, OutboundCodec,
};
use crate::rpc::protocol::Encoding;
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, SinkExt};
use libp2p::core::{OutboundUpgrade, UpgradeInfo};
use std::sync::Arc;
use tokio_util::{
    codec::Framed,
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use types::{EthSpec, ForkContext};
/* Outbound request */

// Combines all the RPC requests into a single enum to implement `UpgradeInfo` and
// `OutboundUpgrade`

#[derive(Debug, Clone)]
pub struct OutboundRequestContainer<E: EthSpec> {
    pub req: OutboundRequest<E>,
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutboundRequest<E: EthSpec> {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    BlocksByRange(OldBlocksByRangeRequest),
    BlocksByRoot(BlocksByRootRequest),
    BlobsByRange(BlobsByRangeRequest),
    BlobsByRoot(BlobsByRootRequest),
    Ping(Ping),
    MetaData(MetadataRequest<E>),
}

impl<E: EthSpec> UpgradeInfo for OutboundRequestContainer<E> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        self.req.supported_protocols()
    }
}

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<E: EthSpec> OutboundRequest<E> {
    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            OutboundRequest::Status(_) => vec![ProtocolId::new(
                SupportedProtocol::StatusV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::Goodbye(_) => vec![ProtocolId::new(
                SupportedProtocol::GoodbyeV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::BlocksByRange(_) => vec![
                ProtocolId::new(SupportedProtocol::BlocksByRangeV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlocksByRangeV1, Encoding::SSZSnappy),
            ],
            OutboundRequest::BlocksByRoot(_) => vec![
                ProtocolId::new(SupportedProtocol::BlocksByRootV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlocksByRootV1, Encoding::SSZSnappy),
            ],
            OutboundRequest::BlobsByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::BlobsByRangeV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::BlobsByRoot(_) => vec![ProtocolId::new(
                SupportedProtocol::BlobsByRootV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::Ping(_) => vec![ProtocolId::new(
                SupportedProtocol::PingV1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::MetaData(_) => vec![
                ProtocolId::new(SupportedProtocol::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::MetaDataV1, Encoding::SSZSnappy),
            ],
        }
    }
    /* These functions are used in the handler for stream management */

    /// Maximum number of responses expected for this request.
    pub fn max_responses(&self) -> u64 {
        match self {
            OutboundRequest::Status(_) => 1,
            OutboundRequest::Goodbye(_) => 0,
            OutboundRequest::BlocksByRange(req) => *req.count(),
            OutboundRequest::BlocksByRoot(req) => req.block_roots().len() as u64,
            OutboundRequest::BlobsByRange(req) => req.max_blobs_requested::<E>(),
            OutboundRequest::BlobsByRoot(req) => req.blob_ids.len() as u64,
            OutboundRequest::Ping(_) => 1,
            OutboundRequest::MetaData(_) => 1,
        }
    }

    pub fn expect_exactly_one_response(&self) -> bool {
        match self {
            OutboundRequest::Status(_) => true,
            OutboundRequest::Goodbye(_) => false,
            OutboundRequest::BlocksByRange(_) => false,
            OutboundRequest::BlocksByRoot(_) => false,
            OutboundRequest::BlobsByRange(_) => false,
            OutboundRequest::BlobsByRoot(_) => false,
            OutboundRequest::Ping(_) => true,
            OutboundRequest::MetaData(_) => true,
        }
    }

    /// Gives the corresponding `SupportedProtocol` to this request.
    pub fn versioned_protocol(&self) -> SupportedProtocol {
        match self {
            OutboundRequest::Status(_) => SupportedProtocol::StatusV1,
            OutboundRequest::Goodbye(_) => SupportedProtocol::GoodbyeV1,
            OutboundRequest::BlocksByRange(req) => match req {
                OldBlocksByRangeRequest::V1(_) => SupportedProtocol::BlocksByRangeV1,
                OldBlocksByRangeRequest::V2(_) => SupportedProtocol::BlocksByRangeV2,
            },
            OutboundRequest::BlocksByRoot(req) => match req {
                BlocksByRootRequest::V1(_) => SupportedProtocol::BlocksByRootV1,
                BlocksByRootRequest::V2(_) => SupportedProtocol::BlocksByRootV2,
            },
            OutboundRequest::BlobsByRange(_) => SupportedProtocol::BlobsByRangeV1,
            OutboundRequest::BlobsByRoot(_) => SupportedProtocol::BlobsByRootV1,
            OutboundRequest::Ping(_) => SupportedProtocol::PingV1,
            OutboundRequest::MetaData(req) => match req {
                MetadataRequest::V1(_) => SupportedProtocol::MetaDataV1,
                MetadataRequest::V2(_) => SupportedProtocol::MetaDataV2,
            },
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            OutboundRequest::BlocksByRange(_) => ResponseTermination::BlocksByRange,
            OutboundRequest::BlocksByRoot(_) => ResponseTermination::BlocksByRoot,
            OutboundRequest::BlobsByRange(_) => ResponseTermination::BlobsByRange,
            OutboundRequest::BlobsByRoot(_) => ResponseTermination::BlobsByRoot,
            OutboundRequest::Status(_) => unreachable!(),
            OutboundRequest::Goodbye(_) => unreachable!(),
            OutboundRequest::Ping(_) => unreachable!(),
            OutboundRequest::MetaData(_) => unreachable!(),
        }
    }
}

/* RPC Response type - used for outbound upgrades */

/* Outbound upgrades */

pub type OutboundFramed<TSocket, E> = Framed<Compat<TSocket>, OutboundCodec<E>>;

impl<TSocket, E> OutboundUpgrade<TSocket> for OutboundRequestContainer<E>
where
    E: EthSpec + Send + 'static,
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = OutboundFramed<TSocket, E>;
    type Error = RPCError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: TSocket, protocol: Self::Info) -> Self::Future {
        // convert to a tokio compatible socket
        let socket = socket.compat();
        let codec = match protocol.encoding {
            Encoding::SSZSnappy => {
                let ssz_snappy_codec = BaseOutboundCodec::new(SSZSnappyOutboundCodec::new(
                    protocol,
                    self.max_rpc_size,
                    self.fork_context.clone(),
                ));
                OutboundCodec::SSZSnappy(ssz_snappy_codec)
            }
        };

        let mut socket = Framed::new(socket, codec);

        async {
            socket.send(self.req).await?;
            socket.close().await?;
            Ok(socket)
        }
        .boxed()
    }
}

impl<E: EthSpec> std::fmt::Display for OutboundRequest<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundRequest::Status(status) => write!(f, "Status Message: {}", status),
            OutboundRequest::Goodbye(reason) => write!(f, "Goodbye: {}", reason),
            OutboundRequest::BlocksByRange(req) => write!(f, "Blocks by range: {}", req),
            OutboundRequest::BlocksByRoot(req) => write!(f, "Blocks by root: {:?}", req),
            OutboundRequest::BlobsByRange(req) => write!(f, "Blobs by range: {:?}", req),
            OutboundRequest::BlobsByRoot(req) => write!(f, "Blobs by root: {:?}", req),
            OutboundRequest::Ping(ping) => write!(f, "Ping: {}", ping.data),
            OutboundRequest::MetaData(_) => write!(f, "MetaData request"),
        }
    }
}
