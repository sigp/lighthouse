//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use handler::RPCHandler;
use libp2p::PeerId;
use libp2p::core::transport::PortUse;
use libp2p::swarm::{
    CloseConnection, ConnectionId, NetworkBehaviour, NotifyHandler, ToSwarm,
    handler::ConnectionHandler,
};
use libp2p::swarm::{ConnectionClosed, FromSwarm, SubstreamProtocol, THandlerInEvent};
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{debug, trace};
use types::{EthSpec, ForkContext};

pub(crate) use handler::{HandlerErr, HandlerEvent};
pub(crate) use methods::{MetaData, MetaDataV2, MetaDataV3, Ping, RpcResponse, RpcSuccessResponse};
pub use protocol::RequestType;

use self::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig};
use self::protocol::RPCProtocol;
use self::self_limiter::SelfRateLimiter;
use crate::rpc::inbound_limiter::{
    ActiveInboundRequest, Admission, InboundRateLimiter, ReadyRequest,
};
use crate::rpc::rate_limiter::RateLimiterItem;
pub use handler::SubstreamId;
use logging::crit;
pub use methods::{
    BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason, LightClientBootstrapRequest,
    ResponseTermination, RpcErrorResponse, StatusMessage,
};
pub use protocol::{Protocol, RPCError};

pub(crate) mod codec;
pub mod config;
mod handler;
mod inbound_limiter;
pub mod methods;
mod outbound;
mod protocol;
mod rate_limiter;
mod self_limiter;

// Maximum number of concurrent requests per protocol ID that a client may issue.
pub const MAX_CONCURRENT_REQUESTS: usize = 2;

/// Composite trait for a request id.
pub trait ReqId: Send + 'static + std::fmt::Debug + Copy + Clone {}
impl<T> ReqId for T where T: Send + 'static + std::fmt::Debug + Copy + Clone {}

/// RPC events sent from Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCSend<Id, E: EthSpec> {
    /// A request sent from Lighthouse.
    ///
    /// The `Id` is given by the application making the request. These
    /// go over *outbound* connections.
    Request(Id, RequestType<E>),
    /// A response sent from Lighthouse.
    ///
    /// The `SubstreamId` must correspond to the RPC-given ID of the original request received from the
    /// peer. The second parameter is a single chunk of a response. These go over *inbound*
    /// connections.
    Response(SubstreamId, RpcResponse<E>),
    /// Lighthouse has requested to terminate the connection with a goodbye message.
    Shutdown(Id, GoodbyeReason),
}

/// RPC events received from outside Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCReceived<Id, E: EthSpec> {
    /// A request received from the outside.
    ///
    /// The `SubstreamId` is given by the `RPCHandler` as it identifies this request with the
    /// *inbound* substream over which it is managed.
    Request(InboundRequestId, RequestType<E>),
    /// A response received from the outside.
    ///
    /// The `Id` corresponds to the application given ID of the original request sent to the
    /// peer. The second parameter is a single chunk of a response. These go over *outbound*
    /// connections.
    Response(Id, RpcSuccessResponse<E>),
    /// Marks a request as completed
    EndOfStream(Id, ResponseTermination),
}

// An identifier for the inbound requests received via Rpc.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct InboundRequestId {
    /// The connection ID of the peer that sent the request.
    connection_id: ConnectionId,
    /// The ID of the substream that sent the request.
    substream_id: SubstreamId,
}

impl InboundRequestId {
    /// Creates an _unchecked_ [`InboundRequestId`].
    ///
    /// [`Rpc`] enforces that [`InboundRequestId`]s are unique and not reused.
    /// This constructor does not, hence the _unchecked_.
    ///
    /// It is primarily meant for allowing manual tests.
    pub fn new_unchecked(connection_id: usize, substream_id: usize) -> Self {
        Self {
            connection_id: ConnectionId::new_unchecked(connection_id),
            substream_id: SubstreamId::new(substream_id),
        }
    }
}

impl<E: EthSpec, Id: std::fmt::Debug> std::fmt::Display for RPCSend<Id, E> {
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
pub struct RPCMessage<Id, E: EthSpec> {
    /// The peer that sent the message.
    pub peer_id: PeerId,
    /// Handler managing this message.
    pub connection_id: ConnectionId,
    /// The message that was sent.
    pub message: Result<RPCReceived<Id, E>, HandlerErr<Id>>,
}

type BehaviourAction<Id, E> = ToSwarm<RPCMessage<Id, E>, RPCSend<Id, E>>;

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<Id: ReqId, E: EthSpec> {
    /// Rate limiter for inbound requests, which delays or rejects requests before they are
    /// executed. Also tracks the active requests and enforces the maximum number of concurrent
    /// requests per protocol per peer, which bounds the delayed requests queue.
    inbound_request_limiter: InboundRateLimiter<E>,
    /// Rate limiter for our own requests.
    outbound_request_limiter: SelfRateLimiter<Id, E>,
    /// Queue of events to be processed.
    events: Vec<BehaviourAction<Id, E>>,
    fork_context: Arc<ForkContext>,
    enable_light_client_server: bool,
    /// A sequential counter indicating when data gets modified.
    seq_number: u64,
}

impl<Id: ReqId, E: EthSpec> RPC<Id, E> {
    pub fn new(
        fork_context: Arc<ForkContext>,
        enable_light_client_server: bool,
        inbound_rate_limiter_config: Option<InboundRateLimiterConfig>,
        outbound_rate_limiter_config: Option<OutboundRateLimiterConfig>,
        seq_number: u64,
    ) -> Self {
        if let Some(config) = &inbound_rate_limiter_config {
            debug!(?config, "Using inbound rate limiting params");
        }
        let inbound_request_limiter =
            InboundRateLimiter::new(inbound_rate_limiter_config, fork_context.clone())
                .expect("Inbound limiter configuration parameters are valid");

        let outbound_request_limiter: SelfRateLimiter<Id, E> =
            SelfRateLimiter::new(outbound_rate_limiter_config, fork_context.clone())
                .expect("Outbound limiter configuration parameters are valid");

        RPC {
            inbound_request_limiter,
            outbound_request_limiter,
            events: Vec::new(),
            fork_context,
            enable_light_client_server,
            seq_number,
        }
    }

    /// Sends an RPC response.
    /// Returns an `Err` if the request does exist in the active inbound requests list.
    pub fn send_response(
        &mut self,
        request_id: InboundRequestId,
        response: RpcResponse<E>,
    ) -> Result<(), RpcResponse<E>> {
        let Some(ActiveInboundRequest {
            peer_id,
            request_type,
        }) = self.inbound_request_limiter.complete_request(request_id)
        else {
            return Err(response);
        };

        // Add the request back to active requests if the response is `Success` and requires stream
        // termination.
        if request_type.protocol().terminator().is_some()
            && matches!(response, RpcResponse::Success(_))
        {
            self.inbound_request_limiter.reinsert_active(
                request_id,
                ActiveInboundRequest {
                    peer_id,
                    request_type: request_type.clone(),
                },
            );
        }

        self.send_response_inner(peer_id, request_id, response);
        Ok(())
    }

    fn send_response_inner(
        &mut self,
        peer_id: PeerId,
        request_id: InboundRequestId,
        response: RpcResponse<E>,
    ) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(request_id.connection_id),
            event: RPCSend::Response(request_id.substream_id, response),
        });
    }

    /// Delivers an inbound request to the application for execution. Pings are additionally
    /// answered here directly.
    fn deliver_request(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        request_id: InboundRequestId,
        request_type: RequestType<E>,
    ) {
        // If we received a Ping, we queue a Pong response.
        if let RequestType::Ping(_) = request_type {
            trace!(%connection_id, %peer_id, "Received Ping, queueing Pong");
            if let Err(response) = self.send_response(
                request_id,
                RpcResponse::Success(RpcSuccessResponse::Pong(Ping {
                    data: self.seq_number,
                })),
            ) {
                crit!(%response, %peer_id, "Unexpected missing request for PONG");
            }
        }

        self.events.push(ToSwarm::GenerateEvent(RPCMessage {
            peer_id,
            connection_id,
            message: Ok(RPCReceived::Request(request_id, request_type)),
        }));
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_request(&mut self, peer_id: PeerId, request_id: Id, req: RequestType<E>) {
        match self
            .outbound_request_limiter
            .allows(peer_id, request_id, req)
        {
            Ok(event) => self.events.push(BehaviourAction::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event,
            }),
            Err(_e) => {
                // Request is logged and queued internally in the self rate limiter.
            }
        }
    }

    /// Lighthouse wishes to disconnect from this peer by sending a Goodbye message. This
    /// gracefully terminates the RPC behaviour with a goodbye message.
    pub fn shutdown(&mut self, peer_id: PeerId, id: Id, reason: GoodbyeReason) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Shutdown(id, reason),
        });
    }

    pub fn update_seq_number(&mut self, seq_number: u64) {
        self.seq_number = seq_number
    }

    /// Send a Ping request to the destination `PeerId` via `ConnectionId`.
    pub fn ping(&mut self, peer_id: PeerId, id: Id) {
        let ping = Ping {
            data: self.seq_number,
        };
        trace!(%peer_id, "Sending Ping");
        self.send_request(peer_id, id, RequestType::Ping(ping));
    }
}

impl<Id, E> NetworkBehaviour for RPC<Id, E>
where
    E: EthSpec,
    Id: ReqId,
{
    type ConnectionHandler = RPCHandler<Id, E>;
    type ToSwarm = RPCMessage<Id, E>;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        let protocol = SubstreamProtocol::new(
            RPCProtocol {
                fork_context: self.fork_context.clone(),
                max_rpc_size: self.fork_context.spec.max_payload_size as usize,
                enable_light_client_server: self.enable_light_client_server,
                phantom: PhantomData,
            },
            (),
        );

        let handler = RPCHandler::new(protocol, self.fork_context.clone(), peer_id, connection_id);

        Ok(handler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        let protocol = SubstreamProtocol::new(
            RPCProtocol {
                fork_context: self.fork_context.clone(),
                max_rpc_size: self.fork_context.spec.max_payload_size as usize,
                enable_light_client_server: self.enable_light_client_server,
                phantom: PhantomData,
            },
            (),
        );

        let handler = RPCHandler::new(protocol, self.fork_context.clone(), peer_id, connection_id);

        Ok(handler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // NOTE: FromSwarm is a non exhaustive enum so updates should be based on release notes more
        // than compiler feedback
        // The self rate limiter holds on to requests and attempts to process them within our rate
        // limits. If a peer disconnects whilst we are self-rate limiting, we want to terminate any
        // pending requests and return an error response to the application.

        if let FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            remaining_established,
            connection_id,
            ..
        }) = event
        {
            // Drop requests that have not yet been delivered for execution. They cannot be
            // answered after their connection closes, even if the peer has another connection.
            self.inbound_request_limiter
                .connection_closed(peer_id, connection_id);

            // If there are still connections remaining, do nothing.
            if remaining_established > 0 {
                return;
            }

            // Get a list of pending requests from the self rate limiter
            for (id, proto) in self.outbound_request_limiter.peer_disconnected(peer_id) {
                let error_msg = ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Err(HandlerErr::Outbound {
                        id,
                        proto,
                        error: RPCError::Disconnected,
                    }),
                });
                self.events.push(error_msg);
            }

            // Replace the pending Requests to the disconnected peer
            // with reports of failed requests.
            self.events.iter_mut().for_each(|event| match &event {
                ToSwarm::NotifyHandler {
                    peer_id: p,
                    event: RPCSend::Request(request_id, req),
                    ..
                } if *p == peer_id => {
                    *event = ToSwarm::GenerateEvent(RPCMessage {
                        peer_id,
                        connection_id,
                        message: Err(HandlerErr::Outbound {
                            id: *request_id,
                            proto: req.versioned_protocol().protocol(),
                            error: RPCError::Disconnected,
                        }),
                    });
                }
                _ => {}
            });
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: <Self::ConnectionHandler as ConnectionHandler>::ToBehaviour,
    ) {
        match event {
            HandlerEvent::Ok(RPCReceived::Request(request_id, request_type)) => {
                // Check the rate limit quota before executing the request, so that no memory is
                // consumed by responses that cannot be sent yet. Requests over the quota are
                // delayed until the quota allows them, or rejected if that would take too long.
                match self
                    .inbound_request_limiter
                    .allows(peer_id, request_id, request_type)
                {
                    Admission::Execute(request_type) => {
                        self.deliver_request(peer_id, connection_id, request_id, request_type);
                    }
                    Admission::Delayed => {
                        // The request is queued inside the limiter and delivered via `poll`.
                    }
                    Admission::Reject(_request_type) => {
                        self.send_response_inner(
                            peer_id,
                            request_id,
                            RpcResponse::Error(
                                RpcErrorResponse::RateLimited,
                                "Rate limited. Request quota exceeded, try again later".into(),
                            ),
                        );
                    }
                    Admission::RejectConcurrent(_request_type) => {
                        self.send_response_inner(
                            peer_id,
                            request_id,
                            RpcResponse::Error(
                                RpcErrorResponse::RateLimited,
                                format!("Rate limited. There are already {MAX_CONCURRENT_REQUESTS} active requests with the same protocol")
                                    .into(),
                            ),
                        );
                    }
                }
            }
            HandlerEvent::Ok(RPCReceived::Response(id, response)) => {
                if response.protocol().terminator().is_none() {
                    // Inform the limiter that a response has been received.
                    self.outbound_request_limiter
                        .request_completed(&peer_id, response.protocol());
                }

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Ok(RPCReceived::Response(id, response)),
                }));
            }
            HandlerEvent::Ok(RPCReceived::EndOfStream(id, response_termination)) => {
                // Inform the limiter that a response has been received.
                self.outbound_request_limiter
                    .request_completed(&peer_id, response_termination.as_protocol());

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Ok(RPCReceived::EndOfStream(id, response_termination)),
                }));
            }
            HandlerEvent::Err(err) => {
                // Inform the limiter that the request has ended with an error.
                match &err {
                    HandlerErr::Inbound { id, .. } => {
                        self.inbound_request_limiter
                            .request_ended(InboundRequestId {
                                connection_id,
                                substream_id: *id,
                            });
                    }
                    HandlerErr::Outbound { proto, .. } => {
                        self.outbound_request_limiter
                            .request_completed(&peer_id, *proto);
                    }
                }

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    connection_id,
                    message: Err(err),
                }));
            }
            HandlerEvent::InboundStreamClosed(substream_id) => {
                self.inbound_request_limiter
                    .request_ended(InboundRequestId {
                        connection_id,
                        substream_id,
                    });
            }
            HandlerEvent::Close(_) => {
                // Handle the close event here.
                self.events.push(ToSwarm::CloseConnection {
                    peer_id,
                    connection: CloseConnection::All,
                });
            }
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Poll::Ready(ready_requests) = self.inbound_request_limiter.poll_ready(cx) {
            for ready_request in ready_requests {
                match ready_request {
                    ReadyRequest::Execute {
                        peer_id,
                        request_id,
                        request_type,
                    } => {
                        self.deliver_request(
                            peer_id,
                            request_id.connection_id,
                            request_id,
                            request_type,
                        );
                    }
                    ReadyRequest::Reject { request_id } => {
                        if let Err(response) = self.send_response(
                            request_id,
                            RpcResponse::Error(
                                RpcErrorResponse::RateLimited,
                                "Rate limited. Request quota exceeded, try again later".into(),
                            ),
                        ) {
                            crit!(%response, ?request_id, "Unexpected missing request");
                        };
                    }
                }
            }
        }

        if let Poll::Ready(event) = self.outbound_request_limiter.poll_ready(cx) {
            self.events.push(event)
        }

        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::config::RateLimiterConfig;
    use crate::rpc::methods::{OldBlocksByRangeRequest, StatusMessage, StatusMessageV1};
    use crate::rpc::rate_limiter::Quota;
    use libp2p::Multiaddr;
    use libp2p::core::{ConnectedPoint, Endpoint};
    use logging::create_test_tracing_subscriber;
    use std::num::NonZeroU64;
    use std::time::Duration;
    use types::{Epoch, Hash256, MainnetEthSpec, Slot};

    /// Creates an RPC behaviour with the given inbound rate limiter quotas.
    fn test_rpc(config: RateLimiterConfig) -> RPC<usize, MainnetEthSpec> {
        create_test_tracing_subscriber();
        let fork_context = Arc::new(ForkContext::new::<MainnetEthSpec>(
            Slot::new(0),
            Hash256::ZERO,
            &MainnetEthSpec::default_spec(),
        ));
        RPC::new(
            fork_context,
            false,
            Some(InboundRateLimiterConfig(config)),
            None,
            0,
        )
    }

    fn status_request() -> RequestType<MainnetEthSpec> {
        RequestType::Status(StatusMessage::V1(StatusMessageV1 {
            fork_digest: [0; 4],
            finalized_root: Hash256::ZERO,
            finalized_epoch: Epoch::new(0),
            head_root: Hash256::ZERO,
            head_slot: Slot::new(0),
        }))
    }

    fn receive_request_on_connection(
        rpc: &mut RPC<usize, MainnetEthSpec>,
        peer_id: PeerId,
        connection_id: usize,
        substream_id: usize,
    ) {
        rpc.on_connection_handler_event(
            peer_id,
            ConnectionId::new_unchecked(connection_id),
            HandlerEvent::Ok(RPCReceived::Request(
                InboundRequestId::new_unchecked(connection_id, substream_id),
                status_request(),
            )),
        );
    }

    fn receive_request(rpc: &mut RPC<usize, MainnetEthSpec>, peer_id: PeerId, substream_id: usize) {
        receive_request_on_connection(rpc, peer_id, 0, substream_id);
    }

    fn close_connection(
        rpc: &mut RPC<usize, MainnetEthSpec>,
        peer_id: PeerId,
        connection_id: usize,
        remaining_established: usize,
    ) {
        let endpoint = ConnectedPoint::Dialer {
            address: Multiaddr::empty(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };
        rpc.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            connection_id: ConnectionId::new_unchecked(connection_id),
            endpoint: &endpoint,
            cause: None,
            remaining_established,
        }));
    }

    /// Simulates the disconnection of the peer's last connection.
    fn disconnect_peer(rpc: &mut RPC<usize, MainnetEthSpec>, peer_id: PeerId) {
        close_connection(rpc, peer_id, 0, 0);
    }

    /// Polls the RPC behaviour until it is pending and returns the produced events.
    fn poll_events(
        rpc: &mut RPC<usize, MainnetEthSpec>,
    ) -> Vec<BehaviourAction<usize, MainnetEthSpec>> {
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let mut events = vec![];
        while let Poll::Ready(event) = rpc.poll(&mut cx) {
            events.push(event);
        }
        events
    }

    fn count_delivered_requests(events: &[BehaviourAction<usize, MainnetEthSpec>]) -> usize {
        events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    ToSwarm::GenerateEvent(RPCMessage {
                        message: Ok(RPCReceived::Request(..)),
                        ..
                    })
                )
            })
            .count()
    }

    fn count_rate_limited_errors(events: &[BehaviourAction<usize, MainnetEthSpec>]) -> usize {
        events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    ToSwarm::NotifyHandler {
                        event: RPCSend::Response(
                            _,
                            RpcResponse::Error(RpcErrorResponse::RateLimited, _)
                        ),
                        ..
                    }
                )
            })
            .count()
    }

    #[tokio::test]
    async fn test_inbound_handler_error_ends_active_request() {
        let mut rpc = test_rpc(RateLimiterConfig::default());
        let peer_id = PeerId::random();

        receive_request(&mut rpc, peer_id, 0);
        assert_eq!(1, count_delivered_requests(&poll_events(&mut rpc)));
        assert_eq!(1, rpc.inbound_request_limiter.active_request_count());

        rpc.on_connection_handler_event(
            peer_id,
            ConnectionId::new_unchecked(0),
            HandlerEvent::Err(HandlerErr::Inbound {
                id: SubstreamId::new(0),
                proto: Protocol::Status,
                error: RPCError::StreamTimeout,
            }),
        );

        assert_eq!(0, rpc.inbound_request_limiter.active_request_count());
    }

    #[tokio::test]
    async fn test_inbound_stream_close_ends_active_request() {
        let mut rpc = test_rpc(RateLimiterConfig::default());
        let peer_id = PeerId::random();
        let connection_id = ConnectionId::new_unchecked(0);

        rpc.on_connection_handler_event(
            peer_id,
            connection_id,
            HandlerEvent::Ok(RPCReceived::Request(
                InboundRequestId::new_unchecked(0, 0),
                RequestType::BlocksByRange(OldBlocksByRangeRequest::new(0, 1, 1)),
            )),
        );
        assert_eq!(1, count_delivered_requests(&poll_events(&mut rpc)));
        assert_eq!(1, rpc.inbound_request_limiter.active_request_count());

        rpc.on_connection_handler_event(
            peer_id,
            connection_id,
            HandlerEvent::InboundStreamClosed(SubstreamId::new(0)),
        );

        assert_eq!(0, rpc.inbound_request_limiter.active_request_count());
    }

    /// Test that rate limited requests are executed once the quota replenishes, instead of being
    /// executed immediately and their responses queued.
    #[tokio::test]
    async fn test_rate_limited_request_delayed() {
        let mut rpc = test_rpc(RateLimiterConfig {
            status_quota: Quota::n_every_millis(NonZeroU64::new(1).unwrap(), 100),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        receive_request(&mut rpc, peer_id, 0);
        receive_request(&mut rpc, peer_id, 1);

        // Only the first request is passed to the application immediately, but both requests
        // are tracked as active.
        assert_eq!(1, count_delivered_requests(&poll_events(&mut rpc)));
        assert_eq!(2, rpc.inbound_request_limiter.active_request_count());

        // Once the quota replenishes, the delayed request is executed.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(1, count_delivered_requests(&poll_events(&mut rpc)));
    }

    /// Test that requests that cannot be executed in time are answered with a rate limited
    /// error.
    #[tokio::test]
    async fn test_rate_limited_request_rejected() {
        let mut rpc = test_rpc(RateLimiterConfig {
            status_quota: Quota::n_every(NonZeroU64::new(1).unwrap(), 60),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        receive_request(&mut rpc, peer_id, 0);
        receive_request(&mut rpc, peer_id, 1);

        // The first request is delivered, while the second would have to be delayed for too
        // long and is rejected.
        let events = poll_events(&mut rpc);
        assert_eq!(1, count_delivered_requests(&events));
        assert_eq!(1, count_rate_limited_errors(&events));

        // The rejected request is no longer tracked.
        assert_eq!(1, rpc.inbound_request_limiter.active_request_count());
    }

    /// Test that delayed requests of a peer are dropped when the peer disconnects.
    #[tokio::test]
    async fn test_delayed_requests_dropped_on_disconnect() {
        let mut rpc = test_rpc(RateLimiterConfig {
            status_quota: Quota::n_every_millis(NonZeroU64::new(1).unwrap(), 100),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        receive_request(&mut rpc, peer_id, 0);
        receive_request(&mut rpc, peer_id, 1);
        assert_eq!(1, count_delivered_requests(&poll_events(&mut rpc)));
        assert_eq!(2, rpc.inbound_request_limiter.active_request_count());

        // Disconnecting the peer drops both its delivered and delayed requests.
        disconnect_peer(&mut rpc, peer_id);
        assert_eq!(0, rpc.inbound_request_limiter.active_request_count());

        // The dropped request is not executed once the quota replenishes.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(0, count_delivered_requests(&poll_events(&mut rpc)));
    }

    /// Test that closing one connection drops only its delayed requests when the peer remains
    /// connected on another connection.
    #[tokio::test]
    async fn test_delayed_requests_dropped_on_connection_close() {
        let mut rpc = test_rpc(RateLimiterConfig {
            status_quota: Quota::n_every_millis(NonZeroU64::new(1).unwrap(), 100),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        receive_request_on_connection(&mut rpc, peer_id, 0, 0);
        assert_eq!(1, count_delivered_requests(&poll_events(&mut rpc)));
        rpc.send_response(
            InboundRequestId::new_unchecked(0, 0),
            RpcResponse::Success(RpcSuccessResponse::Status(match status_request() {
                RequestType::Status(status) => status,
                _ => unreachable!("status_request always returns a status request"),
            })),
        )
        .expect("the first request is active");
        let _ = poll_events(&mut rpc);

        receive_request_on_connection(&mut rpc, peer_id, 0, 1);
        receive_request_on_connection(&mut rpc, peer_id, 1, 0);
        assert_eq!(0, count_delivered_requests(&poll_events(&mut rpc)));
        assert_eq!(2, rpc.inbound_request_limiter.active_request_count());

        // The request queued on connection 0 is dropped, but the request queued on connection 1
        // remains active.
        close_connection(&mut rpc, peer_id, 0, 1);
        assert_eq!(1, rpc.inbound_request_limiter.active_request_count());

        tokio::time::sleep(Duration::from_millis(150)).await;
        let events = poll_events(&mut rpc);
        assert_eq!(1, count_delivered_requests(&events));
        assert!(events.iter().any(|event| matches!(
            event,
            ToSwarm::GenerateEvent(RPCMessage {
                connection_id,
                message: Ok(RPCReceived::Request(..)),
                ..
            }) if *connection_id == ConnectionId::new_unchecked(1)
        )));
    }
}
