//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use futures::future::FutureExt;
use handler::RPCHandler;
use libp2p::core::{connection::ConnectionId, ConnectedPoint};
use libp2p::swarm::{
    protocols_handler::ProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters, SubstreamProtocol,
};
use libp2p::{Multiaddr, PeerId};
use rate_limiter::{RPCRateLimiter as RateLimiter, RPCRateLimiterBuilder, RateLimitedErr};
use slog::{crit, debug, o};
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use types::{EthSpec, ForkContext};

pub(crate) use handler::HandlerErr;
pub(crate) use methods::{MetaData, MetaDataV1, MetaDataV2, Ping, RPCCodedResponse, RPCResponse};
pub(crate) use protocol::{InboundRequest, RPCProtocol};

pub use handler::SubstreamId;
pub use methods::{
    BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason, MaxRequestBlocks,
    RPCResponseErrorCode, RequestId, ResponseTermination, StatusMessage, MAX_REQUEST_BLOCKS,
};
pub(crate) use outbound::OutboundRequest;
pub use protocol::{Protocol, RPCError};

pub(crate) mod codec;
mod handler;
pub mod methods;
mod outbound;
mod protocol;
mod rate_limiter;

/// RPC events sent from Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCSend<TSpec: EthSpec> {
    /// A request sent from Lighthouse.
    ///
    /// The `RequestId` is given by the application making the request. These
    /// go over *outbound* connections.
    Request(RequestId, OutboundRequest<TSpec>),
    /// A response sent from Lighthouse.
    ///
    /// The `SubstreamId` must correspond to the RPC-given ID of the original request received from the
    /// peer. The second parameter is a single chunk of a response. These go over *inbound*
    /// connections.
    Response(SubstreamId, RPCCodedResponse<TSpec>),
    /// Lighthouse has requested to terminate the connection with a goodbye message.
    Shutdown(GoodbyeReason),
}

/// RPC events received from outside Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCReceived<T: EthSpec> {
    /// A request received from the outside.
    ///
    /// The `SubstreamId` is given by the `RPCHandler` as it identifies this request with the
    /// *inbound* substream over which it is managed.
    Request(SubstreamId, InboundRequest<T>),
    /// A response received from the outside.
    ///
    /// The `RequestId` corresponds to the application given ID of the original request sent to the
    /// peer. The second parameter is a single chunk of a response. These go over *outbound*
    /// connections.
    Response(RequestId, RPCResponse<T>),
    /// Marks a request as completed
    EndOfStream(RequestId, ResponseTermination),
}

impl<T: EthSpec> std::fmt::Display for RPCSend<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCSend::Request(id, req) => write!(f, "RPC Request(id: {:?}, {})", id, req),
            RPCSend::Response(id, res) => write!(f, "RPC Response(id: {:?}, {})", id, res),
            RPCSend::Shutdown(reason) => write!(f, "Sending Goodbye: {}", reason),
        }
    }
}

/// Messages sent to the user from the RPC protocol.
pub struct RPCMessage<TSpec: EthSpec> {
    /// The peer that sent the message.
    pub peer_id: PeerId,
    /// Handler managing this message.
    pub conn_id: ConnectionId,
    /// The message that was sent.
    pub event: <RPCHandler<TSpec> as ProtocolsHandler>::OutEvent,
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<TSpec: EthSpec> {
    /// Rate limiter
    limiter: RateLimiter,
    /// Queue of events to be processed.
    events: Vec<NetworkBehaviourAction<RPCSend<TSpec>, RPCMessage<TSpec>>>,
    fork_context: Arc<ForkContext>,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
}

impl<TSpec: EthSpec> RPC<TSpec> {
    pub fn new(fork_context: Arc<ForkContext>, log: slog::Logger) -> Self {
        let log = log.new(o!("service" => "libp2p_rpc"));
        let limiter = RPCRateLimiterBuilder::new()
            .n_every(Protocol::MetaData, 2, Duration::from_secs(5))
            .n_every(Protocol::Ping, 2, Duration::from_secs(10))
            .n_every(Protocol::Status, 5, Duration::from_secs(15))
            .one_every(Protocol::Goodbye, Duration::from_secs(10))
            .n_every(
                Protocol::BlocksByRange,
                methods::MAX_REQUEST_BLOCKS,
                Duration::from_secs(10),
            )
            .n_every(Protocol::BlocksByRoot, 128, Duration::from_secs(10))
            .build()
            .expect("Configuration parameters are valid");
        RPC {
            limiter,
            events: Vec::new(),
            fork_context,
            log,
        }
    }

    /// Sends an RPC response.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_response(
        &mut self,
        peer_id: PeerId,
        id: (ConnectionId, SubstreamId),
        event: RPCCodedResponse<TSpec>,
    ) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(id.0),
            event: RPCSend::Response(id.1, event),
        });
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        event: OutboundRequest<TSpec>,
    ) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Request(request_id, event),
        });
    }

    /// Lighthouse wishes to disconnect from this peer by sending a Goodbye message. This
    /// gracefully terminates the RPC behaviour with a goodbye message.
    pub fn shutdown(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Shutdown(reason),
        });
    }
}

impl<TSpec> NetworkBehaviour for RPC<TSpec>
where
    TSpec: EthSpec,
{
    type ProtocolsHandler = RPCHandler<TSpec>;
    type OutEvent = RPCMessage<TSpec>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        RPCHandler::new(
            SubstreamProtocol::new(
                RPCProtocol {
                    fork_context: self.fork_context.clone(),
                    phantom: PhantomData,
                },
                (),
            ),
            self.fork_context.clone(),
            &self.log,
        )
    }

    // handled by discovery
    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    // Use connection established/closed instead of these currently
    fn inject_connected(&mut self, peer_id: &PeerId) {
        // find the peer's meta-data
        debug!(self.log, "Requesting new peer's metadata"; "peer_id" => %peer_id);
        let rpc_event =
            RPCSend::Request(RequestId::Behaviour, OutboundRequest::MetaData(PhantomData));
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id: *peer_id,
            handler: NotifyHandler::Any,
            event: rpc_event,
        });
    }

    fn inject_disconnected(&mut self, _peer_id: &PeerId) {}

    fn inject_connection_established(
        &mut self,
        _peer_id: &PeerId,
        _: &ConnectionId,
        _connected_point: &ConnectedPoint,
    ) {
    }

    fn inject_connection_closed(
        &mut self,
        _peer_id: &PeerId,
        _: &ConnectionId,
        _connected_point: &ConnectedPoint,
    ) {
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        conn_id: ConnectionId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        if let Ok(RPCReceived::Request(ref id, ref req)) = event {
            // check if the request is conformant to the quota
            match self.limiter.allows(&peer_id, req) {
                Ok(()) => {
                    // send the event to the user
                    self.events
                        .push(NetworkBehaviourAction::GenerateEvent(RPCMessage {
                            peer_id,
                            conn_id,
                            event,
                        }))
                }
                Err(RateLimitedErr::TooLarge) => {
                    // we set the batch sizes, so this is a coding/config err for most protocols
                    let protocol = req.protocol();
                    if matches!(protocol, Protocol::BlocksByRange) {
                        debug!(self.log, "Blocks by range request will never be processed"; "request" => %req);
                    } else {
                        crit!(self.log, "Request size too large to ever be processed"; "protocol" => %protocol);
                    }
                    // send an error code to the peer.
                    // the handler upon receiving the error code will send it back to the behaviour
                    self.send_response(
                        peer_id,
                        (conn_id, *id),
                        RPCCodedResponse::Error(
                            RPCResponseErrorCode::RateLimited,
                            "Rate limited. Request too large".into(),
                        ),
                    );
                }
                Err(RateLimitedErr::TooSoon(wait_time)) => {
                    debug!(self.log, "Request exceeds the rate limit";
                        "request" => %req, "peer_id" => %peer_id, "wait_time_ms" => wait_time.as_millis());
                    // send an error code to the peer.
                    // the handler upon receiving the error code will send it back to the behaviour
                    self.send_response(
                        peer_id,
                        (conn_id, *id),
                        RPCCodedResponse::Error(
                            RPCResponseErrorCode::RateLimited,
                            format!("Wait {:?}", wait_time).into(),
                        ),
                    );
                }
            }
        } else {
            self.events
                .push(NetworkBehaviourAction::GenerateEvent(RPCMessage {
                    peer_id,
                    conn_id,
                    event,
                }));
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        // let the rate limiter prune
        let _ = self.limiter.poll_unpin(cx);
        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }
        Poll::Pending
    }
}
