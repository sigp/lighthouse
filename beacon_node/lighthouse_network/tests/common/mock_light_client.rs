#![cfg(test)]
use fnv::FnvHashMap;
use futures::future::BoxFuture;
use futures::{prelude::*, StreamExt};
use futures::{AsyncRead, AsyncWrite};
use futures::{Sink, SinkExt};
use libp2p::core::connection::ConnectionId;
use libp2p::core::upgrade::{NegotiationError, ProtocolError};
use libp2p::core::PeerId;
use libp2p::core::{UpgradeError, UpgradeInfo};
use libp2p::multiaddr::{Multiaddr, Protocol as MProtocol};
use libp2p::swarm::handler::SubstreamProtocol;
use libp2p::swarm::{
    ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive,
    NegotiatedSubstream, NetworkBehaviour, NetworkBehaviourAction,
};
use libp2p::swarm::{NotifyHandler, PollParameters, SwarmBuilder, SwarmEvent};
use libp2p::{InboundUpgrade, OutboundUpgrade};
use lighthouse_network::rpc::methods::RPCCodedResponse;
use lighthouse_network::rpc::{
    max_rpc_size, BaseOutboundCodec, Encoding, GoodbyeReason,
    HandlerErr, HandlerEvent, HandlerState, InboundRequest, 
    OutboundCodec, OutboundFramed, OutboundInfo, OutboundRequest, OutboundSubstreamState, Protocol,
    ProtocolId, RPCError, RPCMessage, RPCProtocol, RPCReceived, RPCSend,
    ReqId, SSZSnappyOutboundCodec, SubstreamId, Version,
};
use lighthouse_network::NetworkConfig;
use lighthouse_network::{error, Request};
use slog::{crit, debug, o, trace};
use smallvec::SmallVec;
use std::collections::hash_map::Entry;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::sleep_until;
use tokio::time::Instant as TInstant;
use tokio_util::codec::Framed;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::time::DelayQueue;
use types::{EthSpec, ForkContext};

use lighthouse_network::{build_transport, Context as ServiceContext, };

/// The time (in seconds) before a substream that is awaiting a response from the user times out.
pub const RESPONSE_TIMEOUT: u64 = 10;

/// The number of times to retry an outbound upgrade in the case of IO errors.
const IO_ERROR_RETRIES: u8 = 3;

/// Maximum time given to the handler to perform shutdown operations.
const SHUTDOWN_TIMEOUT_SECS: u8 = 15;

pub struct MockLibP2PLightClientService<Id: ReqId, TSpec: EthSpec> {
    pub swarm: libp2p::swarm::Swarm<MockRPC<Id, TSpec>>,
}

impl<Id: ReqId, TSpec: EthSpec> MockLibP2PLightClientService<Id, TSpec> {
    pub async fn new(
        executor: task_executor::TaskExecutor,
        ctx: ServiceContext<'_>,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        let log = log.new(o!("service"=> "libp2p"));
        let config = ctx.config.clone();
        trace!(log, "Libp2p Service starting");
        // initialise the node's ID

        let local_keypair = libp2p::identity::Keypair::generate_secp256k1();
        let local_peer_id = PeerId::from(local_keypair.public());

        let rpc = MockRPC::new(ctx.fork_context.clone(), log.clone());

        let (swarm, _bandwidth) = {
            // Set up the transport - tcp/ws with noise and mplex
            let (transport, bandwidth) = build_transport(local_keypair.clone())
                .map_err(|e| format!("Failed to build transport: {:?}", e))?;

            // use the executor for libp2p
            struct Executor(task_executor::TaskExecutor);
            impl libp2p::swarm::Executor for Executor {
                fn exec(&self, f: Pin<Box<dyn futures::Future<Output = ()> + Send>>) {
                    self.0.spawn(f, "libp2p");
                }
            }

            (
                SwarmBuilder::with_executor(transport, rpc, local_peer_id, Executor(executor))
                    .notify_handler_buffer_size(std::num::NonZeroUsize::new(7).expect("Not zero"))
                    .connection_event_buffer_size(64)
                    .build(),
                bandwidth,
            )
        };

        let mut network = Self { swarm };

        network.start(&config).await?;

        Ok(network)
    }

    async fn start(&mut self, config: &NetworkConfig) -> error::Result<()> {
        let listen_multiaddr = {
            let mut m = Multiaddr::from(config.listen_address);
            m.push(MProtocol::Tcp(config.libp2p_port));
            m
        };

        if let Err(_) = self.swarm.listen_on(listen_multiaddr.clone()) {
            return Err("Libp2p was unable to listen on the given listen address.".into());
        };

        Ok(())
    }

    pub async fn next_event(&mut self) -> Option<SwarmEvent<RPCMessage<Id, TSpec>, RPCError>> {
        futures::future::poll_fn(|cx| self.swarm.poll_next_unpin(cx)).await
    }

    pub fn send_request(&mut self, peer_id: PeerId, request_id: Id, request: Request) {
        self.swarm
            .behaviour_mut()
            .send_request(peer_id, request_id, request.into())
    }
}

pub struct MockRPC<Id: ReqId, TSpec: EthSpec> {
    /// Queue of events to be processed.
    events: Vec<NetworkBehaviourAction<RPCMessage<Id, TSpec>, MockRPCHandler<Id, TSpec>>>,
    fork_context: Arc<ForkContext>,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
}

impl<Id: ReqId, TSpec: EthSpec> MockRPC<Id, TSpec> {
    pub fn new(fork_context: Arc<ForkContext>, log: slog::Logger) -> Self {
        Self {
            events: Vec::new(),
            fork_context,
            log,
        }
    }

    pub fn send_request(&mut self, peer_id: PeerId, request_id: Id, req: OutboundRequest<TSpec>) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: RPCSend::Request(request_id, req),
        })
    }
}

impl<Id, TSpec> NetworkBehaviour for MockRPC<Id, TSpec>
where
    TSpec: EthSpec,
    Id: ReqId,
{
    type ConnectionHandler = MockRPCHandler<Id, TSpec>;
    type OutEvent = RPCMessage<Id, TSpec>;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        MockRPCHandler::new(
            SubstreamProtocol::new(
                RPCProtocol {
                    fork_context: self.fork_context.clone(),
                    max_rpc_size: max_rpc_size(&self.fork_context),
                    enable_light_client_server: true,
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
        self.events
            .push(NetworkBehaviourAction::GenerateEvent(RPCMessage {
                peer_id,
                conn_id,
                event,
            }));
    }

    fn poll(
        &mut self,
        _: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }

        Poll::Pending
    }
}

// We have to reimplement the ConnectionHandler trait for a struct that allows outbound
// light client requests.
pub struct MockRPCHandler<Id, TSpec>
where
    TSpec: EthSpec,
{
    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<RPCProtocol<TSpec>, ()>,

    /// Queue of events to produce in `poll()`.
    events_out: SmallVec<[HandlerEvent<Id, TSpec>; 4]>,

    /// Queue of outbound substreams to open.
    dial_queue: SmallVec<[(Id, OutboundRequest<TSpec>); 4]>,

    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,

    /// Map of outbound substreams that need to be driven to completion.
    outbound_substreams: FnvHashMap<SubstreamId, OutboundInfo<Id, TSpec>>,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    outbound_substreams_delay: DelayQueue<SubstreamId>,

    /// Sequential ID for waiting substreams. For inbound substreams, this is also the inbound request ID.
    current_inbound_substream_id: SubstreamId,

    /// Sequential ID for outbound substreams.
    current_outbound_substream_id: SubstreamId,

    /// Maximum number of concurrent outbound substreams being opened. Value is never modified.
    max_dial_negotiated: u32,

    /// State of the handler.
    state: HandlerState,

    /// Try to negotiate the outbound upgrade a few times if there is an IO error before reporting the request as failed.
    /// This keeps track of the number of attempts.
    outbound_io_error_retries: u8,

    /// Fork specific info.
    fork_context: Arc<ForkContext>,

    /// Waker, to be sure the handler gets polled when needed.
    waker: Option<std::task::Waker>,

    /// Logger for handling RPC streams
    log: slog::Logger,
}

#[derive(Debug, Clone)]
pub struct MockOutboundRequestContainer<TSpec: EthSpec> {
    pub req: OutboundRequest<TSpec>,
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
}

impl<TSpec: EthSpec> UpgradeInfo for MockOutboundRequestContainer<TSpec> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        match self.req {
            OutboundRequest::Status(_) => vec![ProtocolId::new(
                Protocol::Status,
                Version::V1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::Goodbye(_) => vec![ProtocolId::new(
                Protocol::Goodbye,
                Version::V1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::Ping(_) => vec![ProtocolId::new(
                Protocol::Ping,
                Version::V1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::MetaData(_) => vec![
                ProtocolId::new(Protocol::MetaData, Version::V2, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZSnappy),
            ],
            OutboundRequest::LightClientBootstrap(_) => vec![ProtocolId::new(
                Protocol::LightClientBootstrap,
                Version::V1,
                Encoding::SSZSnappy,
            )],
            OutboundRequest::BlocksByRange(_) => vec![],
            OutboundRequest::BlocksByRoot(_) => vec![],
        }
    }
}

// struct ResponseTermination {}

impl<TSocket, TSpec> OutboundUpgrade<TSocket> for MockOutboundRequestContainer<TSpec>
where
    TSpec: EthSpec + Send + 'static,
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = OutboundFramed<TSocket, TSpec>;
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

impl<Id, TSpec> MockRPCHandler<Id, TSpec>
where
    TSpec: EthSpec,
{
    pub fn new(
        listen_protocol: SubstreamProtocol<RPCProtocol<TSpec>, ()>,
        fork_context: Arc<ForkContext>,
        log: &slog::Logger,
    ) -> Self {
        MockRPCHandler {
            listen_protocol,
            events_out: SmallVec::new(),
            dial_queue: SmallVec::new(),
            dial_negotiated: 0,
            outbound_substreams: FnvHashMap::default(),
            outbound_substreams_delay: DelayQueue::new(),
            current_inbound_substream_id: SubstreamId(0),
            current_outbound_substream_id: SubstreamId(0),
            state: HandlerState::Active,
            max_dial_negotiated: 8,
            outbound_io_error_retries: 0,
            fork_context,
            waker: None,
            log: log.clone(),
        }
    }

    /// Initiates the handler's shutdown process, sending an optional Goodbye message to the
    /// peer.
    fn shutdown(&mut self, goodbye_reason: Option<(Id, GoodbyeReason)>) {
        if matches!(self.state, HandlerState::Active) {
            if !self.dial_queue.is_empty() {
                debug!(self.log, "Starting handler shutdown"; "unsent_queued_requests" => self.dial_queue.len());
            }
            // We now drive to completion communications already dialed/established
            while let Some((id, req)) = self.dial_queue.pop() {
                self.events_out.push(Err(HandlerErr::Outbound {
                    error: RPCError::Disconnected,
                    proto: req.protocol(),
                    id,
                }));
            }

            // Queue our goodbye message.
            if let Some((id, reason)) = goodbye_reason {
                self.dial_queue.push((id, OutboundRequest::Goodbye(reason)));
            }

            self.state = HandlerState::ShuttingDown(Box::pin(sleep_until(
                TInstant::now() + Duration::from_secs(SHUTDOWN_TIMEOUT_SECS as u64),
            )));
        }
    }

    /// Opens an outbound substream with a request.
    fn send_request(&mut self, id: Id, req: OutboundRequest<TSpec>) {
        match self.state {
            HandlerState::Active => {
                self.dial_queue.push((id, req));
            }
            _ => self.events_out.push(Err(HandlerErr::Outbound {
                error: RPCError::Disconnected,
                proto: req.protocol(),
                id,
            })),
        }
    }
}

impl<Id, TSpec> ConnectionHandler for MockRPCHandler<Id, TSpec>
where
    TSpec: EthSpec,
    Id: ReqId,
{
    type InEvent = RPCSend<Id, TSpec>;
    type OutEvent = HandlerEvent<Id, TSpec>;
    type Error = RPCError;
    type InboundProtocol = RPCProtocol<TSpec>;
    type OutboundProtocol = MockOutboundRequestContainer<TSpec>;
    type OutboundOpenInfo = (Id, OutboundRequest<TSpec>); // Keep track of the id and the request
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, ()> {
        self.listen_protocol.clone()
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        out: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        request_info: Self::OutboundOpenInfo,
    ) {
        self.dial_negotiated -= 1;
        let (id, request) = request_info;
        let proto = request.protocol();

        // add the stream to substreams if we expect a response, otherwise drop the stream.
        let expected_responses = request.expected_responses();
        if expected_responses > 0 {
            // new outbound request. Store the stream and tag the output.
            let delay_key = self.outbound_substreams_delay.insert(
                self.current_outbound_substream_id,
                Duration::from_secs(RESPONSE_TIMEOUT),
            );
            let awaiting_stream = OutboundSubstreamState::RequestPendingResponse {
                substream: Box::new(out),
                request,
            };
            let expected_responses = if expected_responses > 1 {
                // Currently enforced only for multiple responses
                Some(expected_responses)
            } else {
                None
            };
            if self
                .outbound_substreams
                .insert(
                    self.current_outbound_substream_id,
                    OutboundInfo {
                        state: awaiting_stream,
                        delay_key,
                        proto,
                        remaining_chunks: expected_responses,
                        req_id: id,
                    },
                )
                .is_some()
            {
                crit!(self.log, "Duplicate outbound substream id"; "id" => self.current_outbound_substream_id);
            }
            self.current_outbound_substream_id.0 += 1;
        }
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        substream: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
        _info: Self::InboundOpenInfo,
    ) {
        // only accept new peer requests when active
        if !matches!(self.state, HandlerState::Active) {
            return;
        }

        let (req, _) = substream;

        // If we received a goodbye, shutdown the connection.
        if let InboundRequest::Goodbye(_) = req {
            self.shutdown(None);
        }

        self.events_out.push(Ok(RPCReceived::Request(
            self.current_inbound_substream_id,
            req,
        )));
        self.current_inbound_substream_id.0 += 1;
    }

    fn inject_event(&mut self, rpc_event: Self::InEvent) {
        match rpc_event {
            RPCSend::Request(id, req) => self.send_request(id, req),
            RPCSend::Shutdown(id, reason) => self.shutdown(Some((id, reason))),
            _ => {},
        }
        // In any case, we need the handler to process the event.
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }

    fn inject_dial_upgrade_error(
        &mut self,
        request_info: Self::OutboundOpenInfo,
        error: ConnectionHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Error,
        >,
    ) {
        let (id, req) = request_info;
        if let ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Apply(RPCError::IoError(_))) = error
        {
            self.outbound_io_error_retries += 1;
            if self.outbound_io_error_retries < IO_ERROR_RETRIES {
                self.send_request(id, req);
                return;
            }
        }

        // This dialing is now considered failed
        self.dial_negotiated -= 1;

        self.outbound_io_error_retries = 0;
        // map the error
        let error = match error {
            ConnectionHandlerUpgrErr::Timer => RPCError::InternalError("Timer failed"),
            ConnectionHandlerUpgrErr::Timeout => RPCError::NegotiationTimeout,
            ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Apply(e)) => e,
            ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                RPCError::UnsupportedProtocol
            }
            ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Select(
                NegotiationError::ProtocolError(e),
            )) => match e {
                ProtocolError::IoError(io_err) => RPCError::IoError(io_err.to_string()),
                ProtocolError::InvalidProtocol => {
                    RPCError::InternalError("Protocol was deemed invalid")
                }
                ProtocolError::InvalidMessage | ProtocolError::TooManyProtocols => {
                    // Peer is sending invalid data during the negotiation phase, not
                    // participating in the protocol
                    RPCError::InvalidData("Invalid message during negotiation".to_string())
                }
            },
        };
        self.events_out.push(Err(HandlerErr::Outbound {
            error,
            proto: req.protocol(),
            id,
        }));
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        // Check that we don't have outbound items pending for dialing, nor dialing, nor
        // established. Also check that there are no established inbound substreams.
        // Errors and events need to be reported back, so check those too.
        let should_shutdown = match self.state {
            HandlerState::ShuttingDown(_) => {
                self.dial_queue.is_empty()
                    && self.outbound_substreams.is_empty()
                    && self.events_out.is_empty()
                    && self.dial_negotiated == 0
            }
            HandlerState::Deactivated => {
                // Regardless of events, the timeout has expired. Force the disconnect.
                true
            }
            _ => false,
        };
        if should_shutdown {
            KeepAlive::No
        } else {
            KeepAlive::Yes
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        if let Some(waker) = &self.waker {
            if waker.will_wake(cx.waker()) {
                self.waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(cx.waker().clone());
        }
        // return any events that need to be reported
        if !self.events_out.is_empty() {
            return Poll::Ready(ConnectionHandlerEvent::Custom(self.events_out.remove(0)));
        } else {
            self.events_out.shrink_to_fit();
        }

        // Check if we are shutting down, and if the timer ran out
        if let HandlerState::ShuttingDown(delay) = &mut self.state {
            match delay.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    self.state = HandlerState::Deactivated;
                    debug!(self.log, "Handler deactivated");
                    return Poll::Ready(ConnectionHandlerEvent::Close(RPCError::Disconnected));
                }
                Poll::Pending => {}
            };
        }

        // when deactivated, close all streams
        let deactivated = matches!(self.state, HandlerState::Deactivated);

        // drive outbound streams that need to be processed
        for outbound_id in self.outbound_substreams.keys().copied().collect::<Vec<_>>() {
            // get the state and mark it as poisoned
            let (mut entry, state) = match self.outbound_substreams.entry(outbound_id) {
                Entry::Occupied(mut entry) => {
                    let state = std::mem::replace(
                        &mut entry.get_mut().state,
                        OutboundSubstreamState::Poisoned,
                    );
                    (entry, state)
                }
                Entry::Vacant(_) => unreachable!(),
            };

            match state {
                OutboundSubstreamState::RequestPendingResponse {
                    substream,
                    request: _,
                } if deactivated => {
                    // the handler is deactivated. Close the stream
                    entry.get_mut().state = OutboundSubstreamState::Closing(substream);
                    self.events_out.push(Err(HandlerErr::Outbound {
                        error: RPCError::Disconnected,
                        proto: entry.get().proto,
                        id: entry.get().req_id,
                    }))
                }
                OutboundSubstreamState::RequestPendingResponse {
                    mut substream,
                    request,
                } => match substream.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(response))) => {
                        if request.expected_responses() > 1 && !response.close_after() {
                            let substream_entry = entry.get_mut();
                            let delay_key = &substream_entry.delay_key;
                            // chunks left after this one
                            let remaining_chunks = substream_entry
                                .remaining_chunks
                                .map(|count| count.saturating_sub(1))
                                .unwrap_or_else(|| 0);
                            if remaining_chunks == 0 {
                                // this is the last expected message, close the stream as all expected chunks have been received
                                substream_entry.state = OutboundSubstreamState::Closing(substream);
                            } else {
                                // If the response chunk was expected update the remaining number of chunks expected and reset the Timeout
                                substream_entry.state =
                                    OutboundSubstreamState::RequestPendingResponse {
                                        substream,
                                        request,
                                    };
                                substream_entry.remaining_chunks = Some(remaining_chunks);
                                self.outbound_substreams_delay
                                    .reset(delay_key, Duration::from_secs(RESPONSE_TIMEOUT));
                            }
                        } else {
                            // either this is a single response request or this response closes the
                            // stream
                            entry.get_mut().state = OutboundSubstreamState::Closing(substream);
                        }

                        // Check what type of response we got and report it accordingly
                        let id = entry.get().req_id;
                        let proto = entry.get().proto;

                        let received = match response {
                            RPCCodedResponse::StreamTermination(t) => {
                                Ok(RPCReceived::EndOfStream(id, t))
                            }
                            RPCCodedResponse::Success(resp) => Ok(RPCReceived::Response(id, resp)),
                            RPCCodedResponse::Error(ref code, ref r) => Err(HandlerErr::Outbound {
                                id,
                                proto,
                                error: RPCError::ErrorResponse(*code, r.to_string()),
                            }),
                        };

                        return Poll::Ready(ConnectionHandlerEvent::Custom(received));
                    }
                    Poll::Ready(None) => {
                        // stream closed
                        // if we expected multiple streams send a stream termination,
                        // else report the stream terminating only.
                        //trace!(self.log, "RPC Response - stream closed by remote");
                        // drop the stream
                        let delay_key = &entry.get().delay_key;
                        let request_id = entry.get().req_id;
                        self.outbound_substreams_delay.remove(delay_key);
                        entry.remove_entry();
                        // notify the application error
                        if request.expected_responses() > 1 {
                            // return an end of stream result
                            return Poll::Ready(ConnectionHandlerEvent::Custom(Ok(
                                RPCReceived::EndOfStream(request_id, request.stream_termination()),
                            )));
                        }

                        // else we return an error, stream should not have closed early.
                        let outbound_err = HandlerErr::Outbound {
                            id: request_id,
                            proto: request.protocol(),
                            error: RPCError::IncompleteStream,
                        };
                        return Poll::Ready(ConnectionHandlerEvent::Custom(Err(outbound_err)));
                    }
                    Poll::Pending => {
                        entry.get_mut().state =
                            OutboundSubstreamState::RequestPendingResponse { substream, request }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        // drop the stream
                        let delay_key = &entry.get().delay_key;
                        self.outbound_substreams_delay.remove(delay_key);
                        let outbound_err = HandlerErr::Outbound {
                            id: entry.get().req_id,
                            proto: entry.get().proto,
                            error: e,
                        };
                        entry.remove_entry();
                        return Poll::Ready(ConnectionHandlerEvent::Custom(Err(outbound_err)));
                    }
                },
                OutboundSubstreamState::Closing(mut substream) => {
                    match Sink::poll_close(Pin::new(&mut substream), cx) {
                        Poll::Ready(_) => {
                            // drop the stream and its corresponding timeout
                            let delay_key = &entry.get().delay_key;
                            let protocol = entry.get().proto;
                            let request_id = entry.get().req_id;
                            self.outbound_substreams_delay.remove(delay_key);
                            entry.remove_entry();

                            // report the stream termination to the user
                            //
                            // Streams can be terminated here if a responder tries to
                            // continue sending responses beyond what we would expect. Here
                            // we simply terminate the stream and report a stream
                            // termination to the application
                            let termination = match protocol {
                                _ => None, // all other protocols are do not have multiple responses and we do not inform the user, we simply drop the stream.
                            };

                            if let Some(termination) = termination {
                                return Poll::Ready(ConnectionHandlerEvent::Custom(Ok(
                                    RPCReceived::EndOfStream(request_id, termination),
                                )));
                            }
                        }
                        Poll::Pending => {
                            entry.get_mut().state = OutboundSubstreamState::Closing(substream);
                        }
                    }
                }
                OutboundSubstreamState::Poisoned => {
                    crit!(self.log, "Poisoned outbound substream");
                    unreachable!("Coding Error: Outbound substream is poisoned")
                }
            }
        }

        // establish outbound substreams
        if !self.dial_queue.is_empty() && self.dial_negotiated < self.max_dial_negotiated {
            self.dial_negotiated += 1;
            let (id, req) = self.dial_queue.remove(0);
            self.dial_queue.shrink_to_fit();
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    MockOutboundRequestContainer {
                        req: req.clone(),
                        fork_context: self.fork_context.clone(),
                        max_rpc_size: max_rpc_size(&self.fork_context),
                    },
                    (),
                )
                .map_info(|()| (id, req)),
            });
        }

        // Check if we have completed sending a goodbye, disconnect.
        if let HandlerState::ShuttingDown(_) = self.state {
            if self.dial_queue.is_empty()
                && self.outbound_substreams.is_empty()
                && self.events_out.is_empty()
                && self.dial_negotiated == 0
            {
                return Poll::Ready(ConnectionHandlerEvent::Close(RPCError::Disconnected));
            }
        }

        Poll::Pending
    }
}
