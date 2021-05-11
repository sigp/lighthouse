#![allow(clippy::type_complexity)]
#![allow(clippy::cognitive_complexity)]

use super::protocol::{Protocol, RPCError, RPCProtocol, RpcRequestContainer};
use super::{
    methods::{RPCCodedResponse, RPCResponseErrorCode, RequestId, ResponseTermination},
    RPCRequest,
};
use super::{RPCReceived, RPCSend};
use crate::rpc::protocol::{InboundFramed, OutboundFramed};
use fnv::FnvHashMap;
use futures::prelude::*;
use futures::{Sink, SinkExt};
use libp2p::core::upgrade::{
    InboundUpgrade, NegotiationError, OutboundUpgrade, ProtocolError, UpgradeError,
};
use libp2p::swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use libp2p::swarm::NegotiatedSubstream;
use slog::{crit, debug, trace, warn};
use smallvec::SmallVec;
use std::{
    collections::hash_map::Entry,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{sleep_until, Instant as TInstant, Sleep};
use tokio_util::time::{delay_queue, DelayQueue};
use types::{EthSpec, ForkContext};

/// The time (in seconds) before a substream that is awaiting a response from the user times out.
pub const RESPONSE_TIMEOUT: u64 = 10;

/// The number of times to retry an outbound upgrade in the case of IO errors.
const IO_ERROR_RETRIES: u8 = 3;

/// Maximum time given to the handler to perform shutdown operations.
const SHUTDOWN_TIMEOUT_SECS: u8 = 15;

/// Identifier of inbound and outbound substreams from the handler's perspective.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SubstreamId(usize);

type InboundSubstream<TSpec> = InboundFramed<NegotiatedSubstream, TSpec>;

/// Output of the future handling the send of responses to a peer's request.
type InboundProcessingOutput<TSpec> = (
    InboundSubstream<TSpec>, /* substream */
    Vec<RPCError>,           /* Errors sending messages if any */
    bool,                    /* whether to remove the stream afterwards */
    u64,                     /* Chunks remaining to be sent after this processing finishes */
);

/// Events the handler emits to the behaviour.
type HandlerEvent<T> = Result<RPCReceived<T>, HandlerErr>;

/// An error encountered by the handler.
pub enum HandlerErr {
    /// An error occurred for this peer's request. This can occur during protocol negotiation,
    /// message passing, or if the handler identifies that we are sending an error response to the peer.
    Inbound {
        /// Id of the peer's request for which an error occurred.
        id: SubstreamId,
        /// Information of the negotiated protocol.
        proto: Protocol,
        /// The error that occurred.
        error: RPCError,
    },
    /// An error occurred for this request. Such error can occur during protocol negotiation,
    /// message passing, or if we successfully received a response from the peer, but this response
    /// indicates an error.
    Outbound {
        /// Application-given Id of the request for which an error occurred.
        id: RequestId,
        /// Information of the protocol.
        proto: Protocol,
        /// The error that occurred.
        error: RPCError,
    },
}

/// Implementation of `ProtocolsHandler` for the RPC protocol.
pub struct RPCHandler<TSpec>
where
    TSpec: EthSpec,
{
    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<RPCProtocol<TSpec>, ()>,

    /// Queue of events to produce in `poll()`.
    events_out: SmallVec<[HandlerEvent<TSpec>; 4]>,

    /// Queue of outbound substreams to open.
    dial_queue: SmallVec<[(RequestId, RPCRequest<TSpec>); 4]>,

    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,

    /// Current inbound substreams awaiting processing.
    inbound_substreams: FnvHashMap<SubstreamId, InboundInfo<TSpec>>,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    inbound_substreams_delay: DelayQueue<SubstreamId>,

    /// Map of outbound substreams that need to be driven to completion.
    outbound_substreams: FnvHashMap<SubstreamId, OutboundInfo<TSpec>>,

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

    /// Logger for handling RPC streams
    log: slog::Logger,
}

enum HandlerState {
    /// The handler is active. All messages are sent and received.
    Active,
    /// The handler is shutting_down.
    ///
    /// While in this state the handler rejects new requests but tries to finish existing ones.
    /// Once the timer expires, all messages are killed.
    ShuttingDown(Box<Sleep>),
    /// The handler is deactivated. A goodbye has been sent and no more messages are sent or
    /// received.
    Deactivated,
}

/// Contains the information the handler keeps on established inbound substreams.
struct InboundInfo<TSpec: EthSpec> {
    /// State of the substream.
    state: InboundState<TSpec>,
    /// Responses queued for sending.
    pending_items: Vec<RPCCodedResponse<TSpec>>,
    /// Protocol of the original request we received from the peer.
    protocol: Protocol,
    /// Responses that the peer is still expecting from us.
    remaining_chunks: u64,
    /// Key to keep track of the substream's timeout via `self.inbound_substreams_delay`.
    delay_key: Option<delay_queue::Key>,
}

/// Contains the information the handler keeps on established outbound substreams.
struct OutboundInfo<TSpec: EthSpec> {
    /// State of the substream.
    state: OutboundSubstreamState<TSpec>,
    /// Key to keep track of the substream's timeout via `self.outbound_substreams_delay`.
    delay_key: delay_queue::Key,
    /// Info over the protocol this substream is handling.
    proto: Protocol,
    /// Number of chunks to be seen from the peer's response.
    remaining_chunks: Option<u64>,
    /// `RequestId` as given by the application that sent the request.
    req_id: RequestId,
}

/// State of an inbound substream connection.
enum InboundState<TSpec: EthSpec> {
    /// The underlying substream is not being used.
    Idle(InboundSubstream<TSpec>),
    /// The underlying substream is processing responses.
    Busy(Pin<Box<dyn Future<Output = InboundProcessingOutput<TSpec>> + Send>>),
    /// Temporary state during processing
    Poisoned,
}

/// State of an outbound substream. Either waiting for a response, or in the process of sending.
pub enum OutboundSubstreamState<TSpec: EthSpec> {
    /// A request has been sent, and we are awaiting a response. This future is driven in the
    /// handler because GOODBYE requests can be handled and responses dropped instantly.
    RequestPendingResponse {
        /// The framed negotiated substream.
        substream: Box<OutboundFramed<NegotiatedSubstream, TSpec>>,
        /// Keeps track of the actual request sent.
        request: RPCRequest<TSpec>,
    },
    /// Closing an outbound substream>
    Closing(Box<OutboundFramed<NegotiatedSubstream, TSpec>>),
    /// Temporary state during processing
    Poisoned,
}

impl<TSpec> RPCHandler<TSpec>
where
    TSpec: EthSpec,
{
    pub fn new(
        listen_protocol: SubstreamProtocol<RPCProtocol<TSpec>, ()>,
        fork_context: Arc<ForkContext>,
        log: &slog::Logger,
    ) -> Self {
        RPCHandler {
            listen_protocol,
            events_out: SmallVec::new(),
            dial_queue: SmallVec::new(),
            dial_negotiated: 0,
            inbound_substreams: FnvHashMap::default(),
            outbound_substreams: FnvHashMap::default(),
            inbound_substreams_delay: DelayQueue::new(),
            outbound_substreams_delay: DelayQueue::new(),
            current_inbound_substream_id: SubstreamId(0),
            current_outbound_substream_id: SubstreamId(0),
            state: HandlerState::Active,
            max_dial_negotiated: 8,
            outbound_io_error_retries: 0,
            fork_context,
            log: log.clone(),
        }
    }

    /// Initiates the handler's shutdown process, sending an optional last message to the peer.
    pub fn shutdown(&mut self, final_msg: Option<(RequestId, RPCRequest<TSpec>)>) {
        if matches!(self.state, HandlerState::Active) {
            if !self.dial_queue.is_empty() {
                debug!(self.log, "Starting handler shutdown"; "unsent_queued_requests" => self.dial_queue.len());
            }
            // we now drive to completion communications already dialed/established
            while let Some((id, req)) = self.dial_queue.pop() {
                self.events_out.push(Err(HandlerErr::Outbound {
                    error: RPCError::HandlerRejected,
                    proto: req.protocol(),
                    id,
                }));
            }

            // Queue our final message, if any
            if let Some((id, req)) = final_msg {
                self.dial_queue.push((id, req));
            }

            self.state = HandlerState::ShuttingDown(Box::new(sleep_until(
                TInstant::now() + Duration::from_secs(SHUTDOWN_TIMEOUT_SECS as u64),
            )));
        }
    }

    /// Opens an outbound substream with a request.
    fn send_request(&mut self, id: RequestId, req: RPCRequest<TSpec>) {
        match self.state {
            HandlerState::Active => {
                self.dial_queue.push((id, req));
            }
            _ => self.events_out.push(Err(HandlerErr::Outbound {
                error: RPCError::HandlerRejected,
                proto: req.protocol(),
                id,
            })),
        }
    }

    /// Sends a response to a peer's request.
    // NOTE: If the substream has closed due to inactivity, or the substream is in the
    // wrong state a response will fail silently.
    fn send_response(&mut self, inbound_id: SubstreamId, response: RPCCodedResponse<TSpec>) {
        // check if the stream matching the response still exists
        let inbound_info = if let Some(info) = self.inbound_substreams.get_mut(&inbound_id) {
            info
        } else {
            if !matches!(response, RPCCodedResponse::StreamTermination(..)) {
                // the stream is closed after sending the expected number of responses
                trace!(self.log, "Inbound stream has expired, response not sent";
                    "response" => %response, "id" => inbound_id);
            }
            return;
        };

        // If the response we are sending is an error, report back for handling
        if let RPCCodedResponse::Error(ref code, ref reason) = response {
            self.events_out.push(Err(HandlerErr::Inbound {
                error: RPCError::ErrorResponse(*code, reason.to_string()),
                proto: inbound_info.protocol,
                id: inbound_id,
            }));
        }

        if matches!(self.state, HandlerState::Deactivated) {
            // we no longer send responses after the handler is deactivated
            debug!(self.log, "Response not sent. Deactivated handler";
                "response" => %response, "id" => inbound_id);
            return;
        }
        inbound_info.pending_items.push(response);
    }
}

impl<TSpec> ProtocolsHandler for RPCHandler<TSpec>
where
    TSpec: EthSpec,
{
    type InEvent = RPCSend<TSpec>;
    type OutEvent = HandlerEvent<TSpec>;
    type Error = RPCError;
    type InboundProtocol = RPCProtocol<TSpec>;
    type OutboundProtocol = RpcRequestContainer<TSpec>;
    type OutboundOpenInfo = (RequestId, RPCRequest<TSpec>); // Keep track of the id and the request
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, ()> {
        self.listen_protocol.clone()
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

        let (req, substream) = substream;
        let expected_responses = req.expected_responses();

        // store requests that expect responses
        if expected_responses > 0 {
            // Store the stream and tag the output.
            let delay_key = self.inbound_substreams_delay.insert(
                self.current_inbound_substream_id,
                Duration::from_secs(RESPONSE_TIMEOUT),
            );
            let awaiting_stream = InboundState::Idle(substream);
            self.inbound_substreams.insert(
                self.current_inbound_substream_id,
                InboundInfo {
                    state: awaiting_stream,
                    pending_items: vec![],
                    delay_key: Some(delay_key),
                    protocol: req.protocol(),
                    remaining_chunks: expected_responses,
                },
            );
        }

        self.events_out.push(Ok(RPCReceived::Request(
            self.current_inbound_substream_id,
            req,
        )));
        self.current_inbound_substream_id.0 += 1;
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        out: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        request_info: Self::OutboundOpenInfo,
    ) {
        self.dial_negotiated -= 1;
        let (id, request) = request_info;
        let proto = request.protocol();

        // accept outbound connections only if the handler is not deactivated
        if matches!(self.state, HandlerState::Deactivated) {
            self.events_out.push(Err(HandlerErr::Outbound {
                error: RPCError::HandlerRejected,
                proto,
                id,
            }));
        }

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

    fn inject_event(&mut self, rpc_event: Self::InEvent) {
        match rpc_event {
            RPCSend::Request(id, req) => self.send_request(id, req),
            RPCSend::Response(inbound_id, response) => self.send_response(inbound_id, response),
        }
    }

    fn inject_dial_upgrade_error(
        &mut self,
        request_info: Self::OutboundOpenInfo,
        error: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Error,
        >,
    ) {
        let (id, req) = request_info;
        if let ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(RPCError::IoError(_))) = error {
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
            ProtocolsHandlerUpgrErr::Timer => RPCError::InternalError("Timer failed"),
            ProtocolsHandlerUpgrErr::Timeout => RPCError::NegotiationTimeout,
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(e)) => e,
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
                RPCError::UnsupportedProtocol
            }
            ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(
                NegotiationError::ProtocolError(e),
            )) => match e {
                ProtocolError::IoError(io_err) => RPCError::IoError(io_err.to_string()),
                ProtocolError::InvalidProtocol => {
                    RPCError::InternalError("Protocol was deemed invalid")
                }
                ProtocolError::InvalidMessage | ProtocolError::TooManyProtocols => {
                    // Peer is sending invalid data during the negotiation phase, not
                    // participating in the protocol
                    RPCError::InvalidData
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
                    && self.inbound_substreams.is_empty()
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
        ProtocolsHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        // return any events that need to be reported
        if !self.events_out.is_empty() {
            return Poll::Ready(ProtocolsHandlerEvent::Custom(self.events_out.remove(0)));
        } else {
            self.events_out.shrink_to_fit();
        }

        // Check if we are shutting down, and if the timer ran out
        if let HandlerState::ShuttingDown(delay) = &self.state {
            if delay.is_elapsed() {
                self.state = HandlerState::Deactivated;
                debug!(self.log, "Handler deactivated");
            }
        }

        // purge expired inbound substreams and send an error
        loop {
            match self.inbound_substreams_delay.poll_expired(cx) {
                Poll::Ready(Some(Ok(inbound_id))) => {
                    // handle a stream timeout for various states
                    if let Some(info) = self.inbound_substreams.get_mut(inbound_id.get_ref()) {
                        // the delay has been removed
                        info.delay_key = None;
                        self.events_out.push(Err(HandlerErr::Inbound {
                            error: RPCError::StreamTimeout,
                            proto: info.protocol,
                            id: *inbound_id.get_ref(),
                        }));

                        if info.pending_items.last().map(|l| l.close_after()) == Some(false) {
                            // if the last chunk does not close the stream, append an error
                            info.pending_items.push(RPCCodedResponse::Error(
                                RPCResponseErrorCode::ServerError,
                                "Request timed out".into(),
                            ));
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    warn!(self.log, "Inbound substream poll failed"; "error" => ?e);
                    // drops the peer if we cannot read the delay queue
                    return Poll::Ready(ProtocolsHandlerEvent::Close(RPCError::InternalError(
                        "Could not poll inbound stream timer",
                    )));
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }

        // purge expired outbound substreams
        loop {
            match self.outbound_substreams_delay.poll_expired(cx) {
                Poll::Ready(Some(Ok(outbound_id))) => {
                    if let Some(OutboundInfo { proto, req_id, .. }) =
                        self.outbound_substreams.remove(outbound_id.get_ref())
                    {
                        let outbound_err = HandlerErr::Outbound {
                            id: req_id,
                            proto,
                            error: RPCError::StreamTimeout,
                        };
                        // notify the user
                        return Poll::Ready(ProtocolsHandlerEvent::Custom(Err(outbound_err)));
                    } else {
                        crit!(self.log, "timed out substream not in the books"; "stream_id" => outbound_id.get_ref());
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    warn!(self.log, "Outbound substream poll failed"; "error" => ?e);
                    return Poll::Ready(ProtocolsHandlerEvent::Close(RPCError::InternalError(
                        "Could not poll outbound stream timer",
                    )));
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }

        // when deactivated, close all streams
        let deactivated = matches!(self.state, HandlerState::Deactivated);

        // drive inbound streams that need to be processed
        let mut substreams_to_remove = Vec::new(); // Closed substreams that need to be removed
        for (id, info) in self.inbound_substreams.iter_mut() {
            loop {
                match std::mem::replace(&mut info.state, InboundState::Poisoned) {
                    InboundState::Idle(substream) if !deactivated => {
                        if !info.pending_items.is_empty() {
                            let to_send = std::mem::replace(&mut info.pending_items, vec![]);
                            let fut = process_inbound_substream(
                                substream,
                                info.remaining_chunks,
                                to_send,
                            )
                            .boxed();
                            info.state = InboundState::Busy(Box::pin(fut));
                        } else {
                            info.state = InboundState::Idle(substream);
                            break;
                        }
                    }
                    InboundState::Idle(mut substream) => {
                        // handler is deactivated, close the stream and mark it for removal
                        match substream.close().poll_unpin(cx) {
                            // if we can't close right now, put the substream back and try again later
                            Poll::Pending => info.state = InboundState::Idle(substream),
                            Poll::Ready(res) => {
                                // The substream closed, we remove it
                                substreams_to_remove.push(*id);
                                if let Some(ref delay_key) = info.delay_key {
                                    self.inbound_substreams_delay.remove(delay_key);
                                }
                                if let Err(error) = res {
                                    self.events_out.push(Err(HandlerErr::Inbound {
                                        error,
                                        proto: info.protocol,
                                        id: *id,
                                    }));
                                }
                                if info.pending_items.last().map(|l| l.close_after()) == Some(false)
                                {
                                    // if the request was still active, report back to cancel it
                                    self.events_out.push(Err(HandlerErr::Inbound {
                                        error: RPCError::HandlerRejected,
                                        proto: info.protocol,
                                        id: *id,
                                    }));
                                }
                            }
                        }
                        break;
                    }
                    InboundState::Busy(mut fut) => {
                        // first check if sending finished
                        match fut.poll_unpin(cx) {
                            Poll::Ready((substream, errors, remove, new_remaining_chunks)) => {
                                info.remaining_chunks = new_remaining_chunks;
                                // report any error
                                for error in errors {
                                    self.events_out.push(Err(HandlerErr::Inbound {
                                        error,
                                        proto: info.protocol,
                                        id: *id,
                                    }))
                                }
                                if remove {
                                    substreams_to_remove.push(*id);
                                    if let Some(ref delay_key) = info.delay_key {
                                        self.inbound_substreams_delay.remove(delay_key);
                                    }
                                    break;
                                } else {
                                    // If we are not removing this substream, we reset the timer.
                                    // Each chunk is allowed RESPONSE_TIMEOUT to be sent.
                                    if let Some(ref delay_key) = info.delay_key {
                                        self.inbound_substreams_delay.reset(
                                            delay_key,
                                            Duration::from_secs(RESPONSE_TIMEOUT),
                                        );
                                    }
                                }

                                // The stream may be currently idle. Attempt to process more
                                // elements

                                if !deactivated && !info.pending_items.is_empty() {
                                    let to_send =
                                        std::mem::replace(&mut info.pending_items, vec![]);
                                    let fut = process_inbound_substream(
                                        substream,
                                        info.remaining_chunks,
                                        to_send,
                                    )
                                    .boxed();
                                    info.state = InboundState::Busy(Box::pin(fut));
                                } else {
                                    info.state = InboundState::Idle(substream);
                                    break;
                                }
                            }
                            Poll::Pending => {
                                info.state = InboundState::Busy(fut);
                                break;
                            }
                        };
                    }
                    InboundState::Poisoned => unreachable!("Poisoned inbound substream"),
                }
            }
        }

        // remove closed substreams
        for inbound_id in substreams_to_remove {
            self.inbound_substreams.remove(&inbound_id);
        }

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
                        error: RPCError::HandlerRejected,
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

                        return Poll::Ready(ProtocolsHandlerEvent::Custom(received));
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
                            return Poll::Ready(ProtocolsHandlerEvent::Custom(Ok(
                                RPCReceived::EndOfStream(request_id, request.stream_termination()),
                            )));
                        }

                        // else we return an error, stream should not have closed early.
                        let outbound_err = HandlerErr::Outbound {
                            id: request_id,
                            proto: request.protocol(),
                            error: RPCError::IncompleteStream,
                        };
                        return Poll::Ready(ProtocolsHandlerEvent::Custom(Err(outbound_err)));
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
                        return Poll::Ready(ProtocolsHandlerEvent::Custom(Err(outbound_err)));
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
                                Protocol::BlocksByRange => Some(ResponseTermination::BlocksByRange),
                                Protocol::BlocksByRoot => Some(ResponseTermination::BlocksByRoot),
                                _ => None, // all other protocols are do not have multiple responses and we do not inform the user, we simply drop the stream.
                            };

                            if let Some(termination) = termination {
                                return Poll::Ready(ProtocolsHandlerEvent::Custom(Ok(
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
            return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    RpcRequestContainer {
                        req: req.clone(),
                        fork_context: self.fork_context.clone(),
                    },
                    (),
                )
                .map_info(|()| (id, req)),
            });
        }
        Poll::Pending
    }
}

impl slog::Value for SubstreamId {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        slog::Value::serialize(&self.0, record, key, serializer)
    }
}

/// Sends the queued items to the peer.
async fn process_inbound_substream<TSpec: EthSpec>(
    mut substream: InboundSubstream<TSpec>,
    mut remaining_chunks: u64,
    pending_items: Vec<RPCCodedResponse<TSpec>>,
) -> InboundProcessingOutput<TSpec> {
    let mut errors = Vec::new();
    let mut substream_closed = false;

    for item in pending_items {
        if !substream_closed {
            if matches!(item, RPCCodedResponse::StreamTermination(_)) {
                substream.close().await.unwrap_or_else(|e| errors.push(e));
                substream_closed = true;
            } else {
                remaining_chunks = remaining_chunks.saturating_sub(1);
                // chunks that are not stream terminations get sent, and the stream is closed if
                // the response is an error
                let is_error = matches!(item, RPCCodedResponse::Error(..));

                substream
                    .send(item)
                    .await
                    .unwrap_or_else(|e| errors.push(e));

                if remaining_chunks == 0 || is_error {
                    substream.close().await.unwrap_or_else(|e| errors.push(e));
                    substream_closed = true;
                }
            }
        } else if matches!(item, RPCCodedResponse::StreamTermination(_)) {
            // The sender closed the stream before us, ignore this.
        } else {
            // we have more items after a closed substream, report those as errors
            errors.push(RPCError::InternalError(
                "Sending responses to closed inbound substream",
            ));
        }
    }
    (substream, errors, substream_closed, remaining_chunks)
}
