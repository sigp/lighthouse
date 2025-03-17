//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use handler::RPCHandler;
use libp2p::core::transport::PortUse;
use libp2p::swarm::{
    handler::ConnectionHandler, CloseConnection, ConnectionId, NetworkBehaviour, NotifyHandler,
    ToSwarm,
};
use libp2p::swarm::{ConnectionClosed, FromSwarm, SubstreamProtocol, THandlerInEvent};
use libp2p::PeerId;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tracing::{debug, error, instrument, trace};
use types::{EthSpec, ForkContext};

pub(crate) use handler::{HandlerErr, HandlerEvent};
pub(crate) use methods::{
    MetaData, MetaDataV1, MetaDataV2, MetaDataV3, Ping, RpcResponse, RpcSuccessResponse,
};
pub use protocol::RequestType;

use self::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig};
use self::protocol::RPCProtocol;
use self::self_limiter::SelfRateLimiter;
use crate::rpc::rate_limiter::RateLimiterItem;
use crate::rpc::response_limiter::ResponseLimiter;
pub use handler::SubstreamId;
pub use methods::{
    BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason, LightClientBootstrapRequest,
    ResponseTermination, RpcErrorResponse, StatusMessage,
};
pub use protocol::{max_rpc_size, Protocol, RPCError};

pub(crate) mod codec;
pub mod config;
mod handler;
pub mod methods;
mod outbound;
mod protocol;
mod rate_limiter;
mod response_limiter;
mod self_limiter;

static NEXT_REQUEST_ID: AtomicUsize = AtomicUsize::new(1);

// Maximum number of concurrent requests per protocol ID that a client may issue.
const MAX_CONCURRENT_REQUESTS: usize = 2;

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
    Request(Request<E>),
    /// A response received from the outside.
    ///
    /// The `Id` corresponds to the application given ID of the original request sent to the
    /// peer. The second parameter is a single chunk of a response. These go over *outbound*
    /// connections.
    Response(Id, RpcSuccessResponse<E>),
    /// Marks a request as completed
    EndOfStream(Id, ResponseTermination),
}

/// Rpc `Request` identifier.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestId(usize);

impl RequestId {
    /// Returns the next available [`RequestId`].
    pub fn next() -> Self {
        Self(NEXT_REQUEST_ID.fetch_add(1, Ordering::SeqCst))
    }

    /// Creates an _unchecked_ [`RequestId`].
    ///
    /// [`Rpc`] enforces that [`RequestId`]s are unique and not reused.
    /// This constructor does not, hence the _unchecked_.
    ///
    /// It is primarily meant for allowing manual tests.
    pub fn new_unchecked(id: usize) -> Self {
        Self(id)
    }
}

/// An Rpc Request.
#[derive(Debug, Clone)]
pub struct Request<E: EthSpec> {
    pub id: RequestId,
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub substream_id: SubstreamId,
    pub r#type: RequestType<E>,
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
    pub conn_id: ConnectionId,
    /// The message that was sent.
    pub message: Result<RPCReceived<Id, E>, HandlerErr<Id>>,
}

type BehaviourAction<Id, E> = ToSwarm<RPCMessage<Id, E>, RPCSend<Id, E>>;

pub struct NetworkParams {
    pub max_chunk_size: usize,
    pub ttfb_timeout: Duration,
    pub resp_timeout: Duration,
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<Id: ReqId, E: EthSpec> {
    /// Rate limiter for our responses.
    response_limiter: Option<ResponseLimiter<E>>,
    /// Rate limiter for our own requests.
    outbound_request_limiter: SelfRateLimiter<Id, E>,
    /// Active inbound requests that are awaiting a response.
    active_inbound_requests: HashMap<RequestId, Request<E>>,
    /// Queue of events to be processed.
    events: Vec<BehaviourAction<Id, E>>,
    fork_context: Arc<ForkContext>,
    enable_light_client_server: bool,
    /// Networking constant values
    network_params: NetworkParams,
    /// A sequential counter indicating when data gets modified.
    seq_number: u64,
}

impl<Id: ReqId, E: EthSpec> RPC<Id, E> {
    #[instrument(parent = None,
        level = "trace",
        fields(service = "libp2p_rpc"),
        name = "libp2p_rpc",
        skip_all
    )]
    pub fn new(
        fork_context: Arc<ForkContext>,
        enable_light_client_server: bool,
        inbound_rate_limiter_config: Option<InboundRateLimiterConfig>,
        outbound_rate_limiter_config: Option<OutboundRateLimiterConfig>,
        network_params: NetworkParams,
        seq_number: u64,
    ) -> Self {
        let response_limiter = inbound_rate_limiter_config.map(|config| {
            debug!(?config, "Using response rate limiting params");
            ResponseLimiter::new(config, fork_context.clone())
                .expect("Inbound limiter configuration parameters are valid")
        });

        let outbound_request_limiter: SelfRateLimiter<Id, E> =
            SelfRateLimiter::new(outbound_rate_limiter_config, fork_context.clone())
                .expect("Outbound limiter configuration parameters are valid");

        RPC {
            response_limiter,
            outbound_request_limiter,
            active_inbound_requests: HashMap::new(),
            events: Vec::new(),
            fork_context,
            enable_light_client_server,
            network_params,
            seq_number,
        }
    }

    /// Sends an RPC response.
    ///
    /// The peer must be connected for this to succeed.
    #[instrument(parent = None,
        level = "trace",
        fields(service = "libp2p_rpc"),
        name = "libp2p_rpc",
        skip_all
    )]
    pub fn send_response(
        &mut self,
        peer_id: PeerId,
        _id: (ConnectionId, SubstreamId),
        request_id: RequestId,
        event: RpcResponse<E>,
    ) {
        let Some(request) = self.active_inbound_requests.remove(&request_id) else {
            error!(%peer_id, ?request_id, response = %event, "Request not found in active_inbound_requests. Response not sent");
            return;
        };

        // Add the request back to active requests if the response is not a stream termination.
        if request.r#type.protocol().terminator().is_some()
            && !matches!(event, RpcResponse::StreamTermination(_))
        {
            self.active_inbound_requests
                .insert(request_id, request.clone());
        }

        self.send_response_inner(
            peer_id,
            request.r#type.protocol(),
            request.connection_id,
            request.substream_id,
            event,
        );
    }

    fn send_response_inner(
        &mut self,
        peer_id: PeerId,
        protocol: Protocol,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        response: RpcResponse<E>,
    ) {
        if let Some(response_limiter) = self.response_limiter.as_mut() {
            if !response_limiter.allows(
                peer_id,
                protocol,
                connection_id,
                substream_id,
                response.clone(),
            ) {
                // Response is logged and queued internally in the response limiter.
                return;
            }
        }

        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(connection_id),
            event: RPCSend::Response(substream_id, response),
        });
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    #[instrument(parent = None,
        level = "trace",
        fields(service = "libp2p_rpc"),
        name = "libp2p_rpc",
        skip_all
    )]
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
    #[instrument(parent = None,
        level = "trace",
        fields(service = "libp2p_rpc"),
        name = "libp2p_rpc",
        skip_all
    )]
    pub fn shutdown(&mut self, peer_id: PeerId, id: Id, reason: GoodbyeReason) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Shutdown(id, reason),
        });
    }

    #[instrument(parent = None,
        level = "trace",
        fields(service = "libp2p_rpc"),
        name = "libp2p_rpc",
        skip_all
    )]
    pub fn update_seq_number(&mut self, seq_number: u64) {
        self.seq_number = seq_number
    }

    /// Send a Ping request to the destination `PeerId` via `ConnectionId`.
    #[instrument(parent = None,
        level = "trace",
        fields(service = "libp2p_rpc"),
        name = "libp2p_rpc",
        skip_all
    )]
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
                max_rpc_size: max_rpc_size(&self.fork_context, self.network_params.max_chunk_size),
                enable_light_client_server: self.enable_light_client_server,
                phantom: PhantomData,
                ttfb_timeout: self.network_params.ttfb_timeout,
            },
            (),
        );

        let handler = RPCHandler::new(
            protocol,
            self.fork_context.clone(),
            self.network_params.resp_timeout,
            peer_id,
            connection_id,
        );

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
                max_rpc_size: max_rpc_size(&self.fork_context, self.network_params.max_chunk_size),
                enable_light_client_server: self.enable_light_client_server,
                phantom: PhantomData,
                ttfb_timeout: self.network_params.ttfb_timeout,
            },
            (),
        );

        let handler = RPCHandler::new(
            protocol,
            self.fork_context.clone(),
            self.network_params.resp_timeout,
            peer_id,
            connection_id,
        );

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
            // If there are still connections remaining, do nothing.
            if remaining_established > 0 {
                return;
            }

            // Get a list of pending requests from the self rate limiter
            for (id, proto) in self.outbound_request_limiter.peer_disconnected(peer_id) {
                let error_msg = ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    conn_id: connection_id,
                    message: Err(HandlerErr::Outbound {
                        id,
                        proto,
                        error: RPCError::Disconnected,
                    }),
                });
                self.events.push(error_msg);
            }

            self.active_inbound_requests
                .retain(|_request_id, request| request.peer_id != peer_id);

            if let Some(limiter) = self.response_limiter.as_mut() {
                limiter.peer_disconnected(peer_id);
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
                        conn_id: connection_id,
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
        conn_id: ConnectionId,
        event: <Self::ConnectionHandler as ConnectionHandler>::ToBehaviour,
    ) {
        match event {
            HandlerEvent::Ok(RPCReceived::Request(Request {
                id,
                peer_id,
                connection_id,
                substream_id,
                r#type,
            })) => {
                let request = Request {
                    id,
                    peer_id,
                    connection_id,
                    substream_id,
                    r#type,
                };

                let is_concurrent_request_limit_exceeded = self
                    .active_inbound_requests
                    .iter()
                    .filter(|(_request_id, active_request)| {
                        active_request.peer_id == peer_id
                            && active_request.r#type.protocol() == request.r#type.protocol()
                    })
                    .count()
                    >= MAX_CONCURRENT_REQUESTS;

                // Restricts more than MAX_CONCURRENT_REQUESTS inbound requests from running simultaneously on the same protocol per peer.
                if is_concurrent_request_limit_exceeded {
                    // There is already an active request with the same protocol. Send an error code to the peer.
                    debug!(request = %request.r#type, protocol = %request.r#type.protocol(), %peer_id, "There is an active request with the same protocol");
                    self.send_response_inner(
                        peer_id,
                        request.r#type.protocol(),
                        connection_id,
                        substream_id,
                        RpcResponse::Error(
                            RpcErrorResponse::RateLimited,
                            format!("Rate limited. There are already {MAX_CONCURRENT_REQUESTS} active requests with the same protocol")
                                .into(),
                        ),
                    );
                    return;
                }

                // Requests that are below the limit on the number of simultaneous requests are added to the active inbound requests.
                self.active_inbound_requests.insert(id, request.clone());

                // If we received a Ping, we queue a Pong response.
                if let RequestType::Ping(_) = request.r#type {
                    trace!(connection_id = %conn_id, %peer_id, "Received Ping, queueing Pong");
                    self.send_response(
                        peer_id,
                        (conn_id, substream_id),
                        id,
                        RpcResponse::Success(RpcSuccessResponse::Pong(Ping {
                            data: self.seq_number,
                        })),
                    );
                }

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    conn_id,
                    message: Ok(RPCReceived::Request(request)),
                }));
            }
            HandlerEvent::Ok(RPCReceived::Response(id, response)) => {
                if response.protocol().terminator().is_none() {
                    // Inform the limiter that a response has been received.
                    self.outbound_request_limiter
                        .request_completed(&peer_id, response.protocol());
                }

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    conn_id,
                    message: Ok(RPCReceived::Response(id, response)),
                }));
            }
            HandlerEvent::Ok(RPCReceived::EndOfStream(id, response_termination)) => {
                // Inform the limiter that a response has been received.
                self.outbound_request_limiter
                    .request_completed(&peer_id, response_termination.as_protocol());

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    conn_id,
                    message: Ok(RPCReceived::EndOfStream(id, response_termination)),
                }));
            }
            HandlerEvent::Err(err) => {
                // Inform the limiter that the request has ended with an error.
                let protocol = match err {
                    HandlerErr::Inbound { proto, .. } | HandlerErr::Outbound { proto, .. } => proto,
                };
                self.outbound_request_limiter
                    .request_completed(&peer_id, protocol);

                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    conn_id,
                    message: Err(err),
                }));
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
        if let Some(response_limiter) = self.response_limiter.as_mut() {
            if let Poll::Ready(responses) = response_limiter.poll_ready(cx) {
                for response in responses {
                    self.events.push(ToSwarm::NotifyHandler {
                        peer_id: response.peer_id,
                        handler: NotifyHandler::One(response.connection_id),
                        event: RPCSend::Response(response.substream_id, response.response),
                    });
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
