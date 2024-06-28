//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use futures::future::FutureExt;
use handler::RPCHandler;
use libp2p::swarm::{
    handler::ConnectionHandler, CloseConnection, ConnectionId, NetworkBehaviour, NotifyHandler,
    ToSwarm,
};
use libp2p::swarm::{ConnectionClosed, FromSwarm, SubstreamProtocol, THandlerInEvent};
use libp2p::PeerId;
use rate_limiter::{RPCRateLimiter as RateLimiter, RateLimitedErr};
use slog::{crit, debug, o};
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use types::{EthSpec, ForkContext};

pub(crate) use handler::{HandlerErr, HandlerEvent};
pub(crate) use methods::{MetaData, MetaDataV1, MetaDataV2, Ping, RPCCodedResponse, RPCResponse};
pub(crate) use protocol::InboundRequest;

pub use handler::SubstreamId;
pub use methods::{
    BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason, LightClientBootstrapRequest,
    RPCResponseErrorCode, ResponseTermination, StatusMessage,
};
pub(crate) use outbound::OutboundRequest;
pub use protocol::{max_rpc_size, Protocol, RPCError};

use self::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig};
use self::protocol::RPCProtocol;
use self::self_limiter::SelfRateLimiter;

pub(crate) mod codec;
pub mod config;
mod handler;
pub mod methods;
mod outbound;
mod protocol;
mod rate_limiter;
mod self_limiter;

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
    Request(Id, OutboundRequest<E>),
    /// A response sent from Lighthouse.
    ///
    /// The `SubstreamId` must correspond to the RPC-given ID of the original request received from the
    /// peer. The second parameter is a single chunk of a response. These go over *inbound*
    /// connections.
    Response(SubstreamId, RPCCodedResponse<E>),
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
    Request(SubstreamId, InboundRequest<E>),
    /// A response received from the outside.
    ///
    /// The `Id` corresponds to the application given ID of the original request sent to the
    /// peer. The second parameter is a single chunk of a response. These go over *outbound*
    /// connections.
    Response(Id, RPCResponse<E>),
    /// Marks a request as completed
    EndOfStream(Id, ResponseTermination),
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
    pub event: HandlerEvent<Id, E>,
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
    /// Rate limiter
    limiter: Option<RateLimiter>,
    /// Rate limiter for our own requests.
    self_limiter: Option<SelfRateLimiter<Id, E>>,
    /// Queue of events to be processed.
    events: Vec<BehaviourAction<Id, E>>,
    fork_context: Arc<ForkContext>,
    enable_light_client_server: bool,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
    /// Networking constant values
    network_params: NetworkParams,
}

impl<Id: ReqId, E: EthSpec> RPC<Id, E> {
    pub fn new(
        fork_context: Arc<ForkContext>,
        enable_light_client_server: bool,
        inbound_rate_limiter_config: Option<InboundRateLimiterConfig>,
        outbound_rate_limiter_config: Option<OutboundRateLimiterConfig>,
        log: slog::Logger,
        network_params: NetworkParams,
    ) -> Self {
        let log = log.new(o!("service" => "libp2p_rpc"));

        let inbound_limiter = inbound_rate_limiter_config.map(|config| {
            debug!(log, "Using inbound rate limiting params"; "config" => ?config);
            RateLimiter::new_with_config(config.0)
                .expect("Inbound limiter configuration parameters are valid")
        });

        let self_limiter = outbound_rate_limiter_config.map(|config| {
            SelfRateLimiter::new(config, log.clone()).expect("Configuration parameters are valid")
        });

        RPC {
            limiter: inbound_limiter,
            self_limiter,
            events: Vec::new(),
            fork_context,
            enable_light_client_server,
            log,
            network_params,
        }
    }

    /// Sends an RPC response.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_response(
        &mut self,
        peer_id: PeerId,
        id: (ConnectionId, SubstreamId),
        event: RPCCodedResponse<E>,
    ) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(id.0),
            event: RPCSend::Response(id.1, event),
        });
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_request(&mut self, peer_id: PeerId, request_id: Id, req: OutboundRequest<E>) {
        let event = if let Some(self_limiter) = self.self_limiter.as_mut() {
            match self_limiter.allows(peer_id, request_id, req) {
                Ok(event) => event,
                Err(_e) => {
                    // Request is logged and queued internally in the self rate limiter.
                    return;
                }
            }
        } else {
            ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: RPCSend::Request(request_id, req),
            }
        };

        self.events.push(event);
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
        let log = self
            .log
            .new(slog::o!("peer_id" => peer_id.to_string(), "connection_id" => connection_id.to_string()));
        let handler = RPCHandler::new(
            protocol,
            self.fork_context.clone(),
            &log,
            self.network_params.resp_timeout,
        );

        Ok(handler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
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

        let log = self
            .log
            .new(slog::o!("peer_id" => peer_id.to_string(), "connection_id" => connection_id.to_string()));

        let handler = RPCHandler::new(
            protocol,
            self.fork_context.clone(),
            &log,
            self.network_params.resp_timeout,
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
            if let Some(limiter) = self.self_limiter.as_mut() {
                for (id, proto) in limiter.peer_disconnected(peer_id) {
                    let error_msg = ToSwarm::GenerateEvent(RPCMessage {
                        peer_id,
                        conn_id: connection_id,
                        event: HandlerEvent::Err(HandlerErr::Outbound {
                            id,
                            proto,
                            error: RPCError::Disconnected,
                        }),
                    });
                    self.events.push(error_msg);
                }
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
                        event: HandlerEvent::Err(HandlerErr::Outbound {
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
            HandlerEvent::Ok(RPCReceived::Request(ref id, ref req)) => {
                if let Some(limiter) = self.limiter.as_mut() {
                    // check if the request is conformant to the quota
                    match limiter.allows(&peer_id, req) {
                        Ok(()) => {
                            // send the event to the user
                            self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                                peer_id,
                                conn_id,
                                event,
                            }))
                        }
                        Err(RateLimitedErr::TooLarge) => {
                            // we set the batch sizes, so this is a coding/config err for most protocols
                            let protocol = req.versioned_protocol().protocol();
                            if matches!(
                                protocol,
                                Protocol::BlocksByRange
                                    | Protocol::BlobsByRange
                                    | Protocol::BlocksByRoot
                                    | Protocol::BlobsByRoot
                            ) {
                                debug!(self.log, "Request too large to process"; "request" => %req, "protocol" => %protocol);
                            } else {
                                // Other protocols shouldn't be sending large messages, we should flag the peer kind
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
                    // No rate limiting, send the event to the user
                    self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                        peer_id,
                        conn_id,
                        event,
                    }))
                }
            }
            HandlerEvent::Close(_) => {
                // Handle the close event here.
                self.events.push(ToSwarm::CloseConnection {
                    peer_id,
                    connection: CloseConnection::All,
                });
            }
            _ => {
                self.events.push(ToSwarm::GenerateEvent(RPCMessage {
                    peer_id,
                    conn_id,
                    event,
                }));
            }
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // let the rate limiter prune.
        if let Some(limiter) = self.limiter.as_mut() {
            let _ = limiter.poll_unpin(cx);
        }

        if let Some(self_limiter) = self.self_limiter.as_mut() {
            if let Poll::Ready(event) = self_limiter.poll_ready(cx) {
                self.events.push(event)
            }
        }

        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }

        Poll::Pending
    }
}

impl<Id, E> slog::KV for RPCMessage<Id, E>
where
    E: EthSpec,
    Id: ReqId,
{
    fn serialize(
        &self,
        _record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments("peer_id", &format_args!("{}", self.peer_id))?;
        match &self.event {
            HandlerEvent::Ok(received) => {
                let (msg_kind, protocol) = match received {
                    RPCReceived::Request(_, req) => {
                        ("request", req.versioned_protocol().protocol())
                    }
                    RPCReceived::Response(_, res) => ("response", res.protocol()),
                    RPCReceived::EndOfStream(_, end) => (
                        "end_of_stream",
                        match end {
                            ResponseTermination::BlocksByRange => Protocol::BlocksByRange,
                            ResponseTermination::BlocksByRoot => Protocol::BlocksByRoot,
                            ResponseTermination::BlobsByRange => Protocol::BlobsByRange,
                            ResponseTermination::BlobsByRoot => Protocol::BlobsByRoot,
                        },
                    ),
                };
                serializer.emit_str("msg_kind", msg_kind)?;
                serializer.emit_arguments("protocol", &format_args!("{}", protocol))?;
            }
            HandlerEvent::Err(error) => {
                let (msg_kind, protocol) = match &error {
                    HandlerErr::Inbound { proto, .. } => ("inbound_err", *proto),
                    HandlerErr::Outbound { proto, .. } => ("outbound_err", *proto),
                };
                serializer.emit_str("msg_kind", msg_kind)?;
                serializer.emit_arguments("protocol", &format_args!("{}", protocol))?;
            }
            HandlerEvent::Close(err) => {
                serializer.emit_arguments("handler_close", &format_args!("{}", err))?;
            }
        };

        slog::Result::Ok(())
    }
}
