#![allow(clippy::type_complexity)]
#![allow(clippy::cognitive_complexity)]

use super::methods::{GoodbyeReason, RPCCodedResponse, RPCResponseErrorCode};
use super::outbound::OutboundRequestContainer;
use super::protocol::{max_rpc_size, InboundRequest, Protocol, RPCError, RPCProtocol};
use super::{RPCReceived, RPCSend, ReqId};
use crate::rpc::outbound::{OutboundFramed, OutboundRequest};
use crate::rpc::protocol::InboundFramed;
use fnv::FnvHashMap;
use futures::prelude::*;
use futures::{Sink, SinkExt};
use libp2p::core::upgrade::{
    InboundUpgrade, NegotiationError, OutboundUpgrade, ProtocolError, UpgradeError,
};
use libp2p::swarm::handler::{
    ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive,
    SubstreamProtocol,
};
use libp2p::swarm::NegotiatedSubstream;
use slog::{crit, debug, trace, warn};
use smallvec::SmallVec;
use std::{
    collections::{hash_map::Entry, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
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

/// Maximum number of simultaneous inbound substreams we keep for this peer.
const MAX_INBOUND_SUBSTREAMS: usize = 32;

/// Identifier of inbound and outbound substreams from the handler's perspective.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SubstreamId(usize);

type InboundSubstream<TSpec> = InboundFramed<NegotiatedSubstream, TSpec>;

/// Events the handler emits to the behaviour.
pub type HandlerEvent<Id, T> = Result<RPCReceived<Id, T>, HandlerErr<Id>>;

/// An error encountered by the handler.
#[derive(Debug)]
pub enum HandlerErr<Id> {
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
        id: Id,
        /// Information of the protocol.
        proto: Protocol,
        /// The error that occurred.
        error: RPCError,
    },
}

/// Implementation of `ConnectionHandler` for the RPC protocol.
pub struct RPCHandler<Id, TSpec>
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

    /// Current inbound substreams awaiting processing.
    inbound_substreams: FnvHashMap<SubstreamId, InboundInfo<TSpec>>,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    inbound_substreams_delay: DelayQueue<SubstreamId>,

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

enum HandlerState {
    /// The handler is active. All messages are sent and received.
    Active,
    /// The handler is shutting_down.
    ///
    /// While in this state the handler rejects new requests but tries to finish existing ones.
    /// Once the timer expires, all messages are killed.
    ShuttingDown(Pin<Box<Sleep>>),
    /// The handler is deactivated. A goodbye has been sent and no more messages are sent or
    /// received.
    Deactivated,
}

/// Contains the information the handler keeps on established inbound substreams.
struct InboundInfo<TSpec: EthSpec> {
    /// State of the substream.
    state: InboundState<TSpec>,
    /// Responses queued for sending.
    pending_items: VecDeque<RPCCodedResponse<TSpec>>,
    /// Protocol of the original request we received from the peer.
    protocol: Protocol,
    /// Responses that the peer is still expecting from us.
    remaining_chunks: u64,
    /// Useful to timing how long each request took to process. Currently only used by
    /// BlocksByRange.
    request_start_time: Instant,
    /// Key to keep track of the substream's timeout via `self.inbound_substreams_delay`.
    delay_key: Option<delay_queue::Key>,
}

/// Contains the information the handler keeps on established outbound substreams.
struct OutboundInfo<Id, TSpec: EthSpec> {
    /// State of the substream.
    state: OutboundSubstreamState<TSpec>,
    /// Key to keep track of the substream's timeout via `self.outbound_substreams_delay`.
    delay_key: delay_queue::Key,
    /// Info over the protocol this substream is handling.
    proto: Protocol,
    /// Number of chunks to be seen from the peer's response.
    remaining_chunks: Option<u64>,
    /// `Id` as given by the application that sent the request.
    req_id: Id,
}

/// State of an inbound substream connection.
enum InboundState<TSpec: EthSpec> {
    /// The underlying substream is not being used.
    Idle(InboundSubstream<TSpec>),
    /// The underlying substream is processing responses.
    /// The return value of the future is (substream, stream_was_closed). The stream_was_closed boolean
    /// indicates if the stream was closed due to an error or successfully completing a response.
    Busy(Pin<Box<dyn Future<Output = Result<(InboundSubstream<TSpec>, bool), RPCError>> + Send>>),
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
        request: OutboundRequest<TSpec>,
    },
    /// Closing an outbound substream>
    Closing(Box<OutboundFramed<NegotiatedSubstream, TSpec>>),
    /// Temporary state during processing
    Poisoned,
}

impl<Id, TSpec> RPCHandler<Id, TSpec>
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
                    proto: req.versioned_protocol().protocol(),
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
                proto: req.versioned_protocol().protocol(),
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
                trace!(self.log, "Inbound stream has expired. Response not sent";
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
        inbound_info.pending_items.push_back(response);
    }
}

impl<Id, TSpec> ConnectionHandler for RPCHandler<Id, TSpec>
where
    TSpec: EthSpec,
    Id: ReqId,
{
    type InEvent = RPCSend<Id, TSpec>;
    type OutEvent = HandlerEvent<Id, TSpec>;
    type Error = RPCError;
    type InboundProtocol = RPCProtocol<TSpec>;
    type OutboundProtocol = OutboundRequestContainer<TSpec>;
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
        let proto = request.versioned_protocol().protocol();

        // accept outbound connections only if the handler is not deactivated
        if matches!(self.state, HandlerState::Deactivated) {
            self.events_out.push(Err(HandlerErr::Outbound {
                error: RPCError::Disconnected,
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
            if self.inbound_substreams.len() < MAX_INBOUND_SUBSTREAMS {
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
                        pending_items: VecDeque::with_capacity(std::cmp::min(
                            expected_responses,
                            128,
                        ) as usize),
                        delay_key: Some(delay_key),
                        protocol: req.versioned_protocol().protocol(),
                        request_start_time: Instant::now(),
                        remaining_chunks: expected_responses,
                    },
                );
            } else {
                self.events_out.push(Err(HandlerErr::Inbound {
                    id: self.current_inbound_substream_id,
                    proto: req.versioned_protocol().protocol(),
                    error: RPCError::HandlerRejected,
                }));
                return self.shutdown(None);
            }
        }

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
            RPCSend::Response(inbound_id, response) => self.send_response(inbound_id, response),
            RPCSend::Shutdown(id, reason) => self.shutdown(Some((id, reason))),
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
            proto: req.versioned_protocol().protocol(),
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

                        if info.pending_items.back().map(|l| l.close_after()) == Some(false) {
                            // if the last chunk does not close the stream, append an error
                            info.pending_items.push_back(RPCCodedResponse::Error(
                                RPCResponseErrorCode::ServerError,
                                "Request timed out".into(),
                            ));
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    warn!(self.log, "Inbound substream poll failed"; "error" => ?e);
                    // drops the peer if we cannot read the delay queue
                    return Poll::Ready(ConnectionHandlerEvent::Close(RPCError::InternalError(
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
                        return Poll::Ready(ConnectionHandlerEvent::Custom(Err(outbound_err)));
                    } else {
                        crit!(self.log, "timed out substream not in the books"; "stream_id" => outbound_id.get_ref());
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    warn!(self.log, "Outbound substream poll failed"; "error" => ?e);
                    return Poll::Ready(ConnectionHandlerEvent::Close(RPCError::InternalError(
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
                    // This state indicates that we are not currently sending any messages to the
                    // peer. We need to check if there are messages to send, if so, start the
                    // sending process.
                    InboundState::Idle(substream) if !deactivated => {
                        // Process one more message if one exists.
                        if let Some(message) = info.pending_items.pop_front() {
                            // If this is the last chunk, terminate the stream.
                            let last_chunk = info.remaining_chunks <= 1;
                            let fut =
                                send_message_to_inbound_substream(substream, message, last_chunk)
                                    .boxed();
                            // Update the state and try to process this further.
                            info.state = InboundState::Busy(Box::pin(fut));
                        } else {
                            // There is nothing left to process. Set the stream to idle and
                            // move on to the next one.
                            info.state = InboundState::Idle(substream);
                            break;
                        }
                    }
                    // This state indicates we are not sending at the moment, and the handler is in
                    // the process of closing the connection to the peer.
                    InboundState::Idle(mut substream) => {
                        // Handler is deactivated, close the stream and mark it for removal
                        match substream.close().poll_unpin(cx) {
                            // if we can't close right now, put the substream back and try again
                            // immediately, continue to do this until we close the substream.
                            Poll::Pending => info.state = InboundState::Idle(substream),
                            Poll::Ready(res) => {
                                // The substream closed, we remove it from the mapping and remove
                                // the timeout
                                substreams_to_remove.push(*id);
                                if let Some(ref delay_key) = info.delay_key {
                                    self.inbound_substreams_delay.remove(delay_key);
                                }
                                // If there was an error in shutting down the substream report the
                                // error
                                if let Err(error) = res {
                                    self.events_out.push(Err(HandlerErr::Inbound {
                                        error,
                                        proto: info.protocol,
                                        id: *id,
                                    }));
                                }
                                // If there are still requests to send, report that we are in the
                                // process of closing a connection to the peer and that we are not
                                // processing these excess requests.
                                if info.pending_items.back().map(|l| l.close_after()) == Some(false)
                                {
                                    // if the request was still active, report back to cancel it
                                    self.events_out.push(Err(HandlerErr::Inbound {
                                        error: RPCError::Disconnected,
                                        proto: info.protocol,
                                        id: *id,
                                    }));
                                }
                            }
                        }
                        break;
                    }
                    // This state indicates that there are messages to send back to the peer.
                    // The future here is built by the `process_inbound_substream` function. The
                    // output returns a substream and whether it was closed in this operation.
                    InboundState::Busy(mut fut) => {
                        // Check if the future has completed (i.e we have completed sending all our
                        // pending items)
                        match fut.poll_unpin(cx) {
                            // The pending messages have been sent successfully
                            Poll::Ready(Ok((substream, substream_was_closed)))
                                if !substream_was_closed =>
                            {
                                // The substream is still active, decrement the remaining
                                // chunks expected.
                                info.remaining_chunks = info.remaining_chunks.saturating_sub(1);

                                // If this substream has not ended, we reset the timer.
                                // Each chunk is allowed RESPONSE_TIMEOUT to be sent.
                                if let Some(ref delay_key) = info.delay_key {
                                    self.inbound_substreams_delay
                                        .reset(delay_key, Duration::from_secs(RESPONSE_TIMEOUT));
                                }

                                // The stream may be currently idle. Attempt to process more
                                // elements
                                if !deactivated && !info.pending_items.is_empty() {
                                    // Process one more message if one exists.
                                    if let Some(message) = info.pending_items.pop_front() {
                                        // If this is the last chunk, terminate the stream.
                                        let last_chunk = info.remaining_chunks <= 1;
                                        let fut = send_message_to_inbound_substream(
                                            substream, message, last_chunk,
                                        )
                                        .boxed();
                                        // Update the state and try to process this further.
                                        info.state = InboundState::Busy(Box::pin(fut));
                                    }
                                } else {
                                    // There is nothing left to process. Set the stream to idle and
                                    // move on to the next one.
                                    info.state = InboundState::Idle(substream);
                                    break;
                                }
                            }
                            // The pending messages have been sent successfully and the stream has
                            // terminated
                            Poll::Ready(Ok((_substream, _substream_was_closed))) => {
                                // The substream has closed. Remove the timeout related to the
                                // substream.
                                substreams_to_remove.push(*id);
                                if let Some(ref delay_key) = info.delay_key {
                                    self.inbound_substreams_delay.remove(delay_key);
                                }

                                // BlocksByRange is the one that typically consumes the most time.
                                // Its useful to log when the request was completed.
                                if matches!(info.protocol, Protocol::BlocksByRange) {
                                    debug!(self.log, "BlocksByRange Response sent"; "duration" => Instant::now().duration_since(info.request_start_time).as_secs());
                                }

                                // There is nothing more to process on this substream as it has
                                // been closed. Move on to the next one.
                                break;
                            }
                            // An error occurred when trying to send a response.
                            // This means we terminate the substream.
                            Poll::Ready(Err(error)) => {
                                // Remove the stream timeout from the mapping
                                substreams_to_remove.push(*id);
                                if let Some(ref delay_key) = info.delay_key {
                                    self.inbound_substreams_delay.remove(delay_key);
                                }
                                // Report the error that occurred during the send process
                                self.events_out.push(Err(HandlerErr::Inbound {
                                    error,
                                    proto: info.protocol,
                                    id: *id,
                                }));

                                if matches!(info.protocol, Protocol::BlocksByRange) {
                                    debug!(self.log, "BlocksByRange Response failed"; "duration" => info.request_start_time.elapsed().as_secs());
                                }
                                break;
                            }
                            // The sending future has not completed. Leave the state as busy and
                            // try to progress later.
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

        // Remove closed substreams
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
                            proto: request.versioned_protocol().protocol(),
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

                            if let Some(termination) = protocol.terminator() {
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
                    OutboundRequestContainer {
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
                && self.inbound_substreams.is_empty()
                && self.events_out.is_empty()
                && self.dial_negotiated == 0
            {
                return Poll::Ready(ConnectionHandlerEvent::Close(RPCError::Disconnected));
            }
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

/// Creates a future that can be polled that will send any queued message to the peer.
///
/// This function returns the given substream, along with whether it has been closed or not. Any
/// error that occurred with sending a message is reported also.
async fn send_message_to_inbound_substream<TSpec: EthSpec>(
    mut substream: InboundSubstream<TSpec>,
    message: RPCCodedResponse<TSpec>,
    last_chunk: bool,
) -> Result<(InboundSubstream<TSpec>, bool), RPCError> {
    if matches!(message, RPCCodedResponse::StreamTermination(_)) {
        substream.close().await.map(|_| (substream, true))
    } else {
        // chunks that are not stream terminations get sent, and the stream is closed if
        // the response is an error
        let is_error = matches!(message, RPCCodedResponse::Error(..));

        let send_result = substream.send(message).await;

        // If we need to close the substream, do so and return the result.
        if last_chunk || is_error || send_result.is_err() {
            let close_result = substream.close().await.map(|_| (substream, true));
            // If there was an error in sending, return this error, otherwise, return the
            // result of closing the substream.
            if let Err(e) = send_result {
                return Err(e);
            } else {
                return close_result;
            }
        }
        // Everything worked as expected return the result.
        send_result.map(|_| (substream, false))
    }
}
