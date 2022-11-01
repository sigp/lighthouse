//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use futures::future::FutureExt;
use handler::{HandlerEvent, RPCHandler};
use libp2p::core::connection::ConnectionId;
use libp2p::swarm::{
    handler::ConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters, SubstreamProtocol,
};
use libp2p::PeerId;
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
    RPCResponseErrorCode, ResponseTermination, StatusMessage, MAX_REQUEST_BLOCKS,
};
pub(crate) use outbound::OutboundRequest;
pub use protocol::{max_rpc_size, Protocol, RPCError};

pub(crate) mod codec;
mod handler;
pub mod methods;
mod outbound;
mod protocol;
mod rate_limiter;

/// Composite trait for a request id.
pub trait ReqId: Send + 'static + std::fmt::Debug + Copy + Clone {}
impl<T> ReqId for T where T: Send + 'static + std::fmt::Debug + Copy + Clone {}

/// RPC events sent from Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCSend<Id, TSpec: EthSpec> {
    /// A request sent from Lighthouse.
    ///
    /// The `Id` is given by the application making the request. These
    /// go over *outbound* connections.
    Request(Id, OutboundRequest<TSpec>),
    /// A response sent from Lighthouse.
    ///
    /// The `SubstreamId` must correspond to the RPC-given ID of the original request received from the
    /// peer. The second parameter is a single chunk of a response. These go over *inbound*
    /// connections.
    Response(SubstreamId, RPCCodedResponse<TSpec>),
    /// Lighthouse has requested to terminate the connection with a goodbye message.
    Shutdown(Id, GoodbyeReason),
}

/// RPC events received from outside Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCReceived<Id, T: EthSpec> {
    /// A request received from the outside.
    ///
    /// The `SubstreamId` is given by the `RPCHandler` as it identifies this request with the
    /// *inbound* substream over which it is managed.
    Request(SubstreamId, InboundRequest<T>),
    /// A response received from the outside.
    ///
    /// The `Id` corresponds to the application given ID of the original request sent to the
    /// peer. The second parameter is a single chunk of a response. These go over *outbound*
    /// connections.
    Response(Id, RPCResponse<T>),
    /// Marks a request as completed
    EndOfStream(Id, ResponseTermination),
}

impl<T: EthSpec, Id: std::fmt::Debug> std::fmt::Display for RPCSend<Id, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCSend::Request(id, req) => write!(f, "RPC Request(id: {:?}, {})", id, req),
            RPCSend::Response(id, res) => write!(f, "RPC Response(id: {:?}, {})", id, res),
            RPCSend::Shutdown(_id, reason) => write!(f, "Sending Goodbye: {}", reason),
        }
    }
}

/// Messages sent to the user from the RPC protocol.
#[derive(Debug)]
pub struct RPCMessage<Id, TSpec: EthSpec> {
    /// The peer that sent the message.
    pub peer_id: PeerId,
    /// Handler managing this message.
    pub conn_id: ConnectionId,
    /// The message that was sent.
    pub event: HandlerEvent<Id, TSpec>,
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<Id: ReqId, TSpec: EthSpec> {
    /// Rate limiter
    limiter: RateLimiter,
    /// Queue of events to be processed.
    events: Vec<NetworkBehaviourAction<RPCMessage<Id, TSpec>, RPCHandler<Id, TSpec>>>,
    fork_context: Arc<ForkContext>,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
}

impl<Id: ReqId, TSpec: EthSpec> RPC<Id, TSpec> {
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
    pub fn send_request(&mut self, peer_id: PeerId, request_id: Id, event: OutboundRequest<TSpec>) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Request(request_id, event),
        });
    }

    /// Lighthouse wishes to disconnect from this peer by sending a Goodbye message. This
    /// gracefully terminates the RPC behaviour with a goodbye message.
    pub fn shutdown(&mut self, peer_id: PeerId, id: Id, reason: GoodbyeReason) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Shutdown(id, reason),
        });
    }
}

impl<Id, TSpec> NetworkBehaviour for RPC<Id, TSpec>
where
    TSpec: EthSpec,
    Id: ReqId,
{
    type ConnectionHandler = RPCHandler<Id, TSpec>;
    type OutEvent = RPCMessage<Id, TSpec>;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        RPCHandler::new(
            SubstreamProtocol::new(
                RPCProtocol {
                    fork_context: self.fork_context.clone(),
                    max_rpc_size: max_rpc_size(&self.fork_context),
                    phantom: PhantomData,
                },
                (),
            ),
            self.fork_context.clone(),
            &self.log,
        )
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        conn_id: ConnectionId,
        event: <Self::ConnectionHandler as ConnectionHandler>::OutEvent,
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
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        // let the rate limiter prune
        let _ = self.limiter.poll_unpin(cx);
        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }
        Poll::Pending
    }
}

impl<Id, TSpec> slog::KV for RPCMessage<Id, TSpec>
where
    TSpec: EthSpec,
    Id: ReqId,
{
    fn serialize(
        &self,
        _record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments("peer_id", &format_args!("{}", self.peer_id))?;
        let (msg_kind, protocol) = match &self.event {
            Ok(received) => match received {
                RPCReceived::Request(_, req) => ("request", req.protocol()),
                RPCReceived::Response(_, res) => ("response", res.protocol()),
                RPCReceived::EndOfStream(_, end) => (
                    "end_of_stream",
                    match end {
                        ResponseTermination::BlocksByRange => Protocol::BlocksByRange,
                        ResponseTermination::BlocksByRoot => Protocol::BlocksByRoot,
                    },
                ),
            },
            Err(error) => match &error {
                HandlerErr::Inbound { proto, .. } => ("inbound_err", *proto),
                HandlerErr::Outbound { proto, .. } => ("outbound_err", *proto),
            },
        };
        serializer.emit_str("msg_kind", msg_kind)?;
        serializer.emit_arguments("protocol", &format_args!("{}", protocol))?;

        slog::Result::Ok(())
    }
}
