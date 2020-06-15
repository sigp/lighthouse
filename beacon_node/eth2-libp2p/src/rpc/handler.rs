#![allow(clippy::type_complexity)]
#![allow(clippy::cognitive_complexity)]

use super::methods::{RPCCodedResponse, RequestId, ResponseTermination};
use super::protocol::{Protocol, RPCError, RPCProtocol, RPCRequest};
use super::{RPCReceived, RPCSend};
use crate::rpc::protocol::{InboundFramed, OutboundFramed};
use fnv::FnvHashMap;
use futures::prelude::*;
use libp2p::core::upgrade::{
    InboundUpgrade, NegotiationError, OutboundUpgrade, ProtocolError, UpgradeError,
};
use libp2p::swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use libp2p::swarm::NegotiatedSubstream;
use slog::{crit, debug, error, trace, warn};
use smallvec::SmallVec;
use std::{
    collections::hash_map::Entry,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::time::{delay_queue, DelayQueue};
use types::EthSpec;

//TODO: Implement check_timeout() on the substream types

/// The time (in seconds) before a substream that is awaiting a response from the user times out.
pub const RESPONSE_TIMEOUT: u64 = 10;

/// The number of times to retry an outbound upgrade in the case of IO errors.
const IO_ERROR_RETRIES: u8 = 3;

/// Identifier of inbound and outbound substreams from the handler's perspective.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SubstreamId(usize);

/// An error encoutered by the handler.
pub enum HandlerErr {
    /// An error ocurred for this peer's request. This can occurr during protocol negotiation,
    /// message passing, or if the handler identifies that we are sending an error reponse to the peer.
    Inbound {
        /// Id of the peer's request for which an error occurred.
        id: SubstreamId,
        /// Information of the negotiated protocol.
        proto: Protocol,
        /// The error that ocurred.
        error: RPCError,
    },
    /// An error ocurred for this request. Such error can occurr during protocol negotiation,
    /// message passing, or if we successfully received a response from the peer, but this response
    /// indicates an error.
    Outbound {
        /// Application-given Id of the request for which an error occurred.
        id: RequestId,
        /// Information of the protocol.
        proto: Protocol,
        /// The error that ocurred.
        error: RPCError,
    },
}

/// Implementation of `ProtocolsHandler` for the RPC protocol.
pub struct RPCHandler<TSpec>
where
    TSpec: EthSpec,
{
    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<RPCProtocol<TSpec>>,

    /// Errors ocurring on outbound and inbound connections queued for reporting back.
    pending_errors: Vec<HandlerErr>,

    /// Queue of events to produce in `poll()`.
    events_out: SmallVec<[RPCReceived<TSpec>; 4]>,

    /// Queue of outbound substreams to open.
    dial_queue: SmallVec<[(RequestId, RPCRequest<TSpec>); 4]>,

    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,

    /// Current inbound substreams awaiting processing.
    inbound_substreams: FnvHashMap<
        SubstreamId,
        (
            InboundSubstreamState<TSpec>,
            Option<delay_queue::Key>,
            Protocol,
        ),
    >,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    inbound_substreams_delay: DelayQueue<SubstreamId>,

    /// Map of outbound substreams that need to be driven to completion.
    outbound_substreams: FnvHashMap<SubstreamId, OutboundInfo<TSpec>>,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    outbound_substreams_delay: DelayQueue<SubstreamId>,

    /// Map of outbound items that are queued as the stream processes them.
    queued_outbound_items: FnvHashMap<SubstreamId, Vec<RPCCodedResponse<TSpec>>>,

    /// Sequential ID for waiting substreams. For inbound substreams, this is also the inbound request ID.
    current_inbound_substream_id: SubstreamId,

    /// Sequential ID for outbound substreams.
    current_outbound_substream_id: SubstreamId,

    /// Maximum number of concurrent outbound substreams being opened. Value is never modified.
    max_dial_negotiated: u32,

    /// Value to return from `connection_keep_alive`.
    keep_alive: KeepAlive,

    /// After the given duration has elapsed, an inactive connection will shutdown.
    inactive_timeout: Duration,

    /// Try to negotiate the outbound upgrade a few times if there is an IO error before reporting the request as failed.
    /// This keeps track of the number of attempts.
    outbound_io_error_retries: u8,

    /// Logger for handling RPC streams
    log: slog::Logger,
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
    // TODO: removing the option could allow clossing the streams after the number of
    // expected responses is met for all protocols.
    // TODO: the type of this is  wrong
    remaining_chunks: Option<usize>,
    /// RequestId as given by the application that sent the request.
    req_id: RequestId,
}

pub enum InboundSubstreamState<TSpec>
where
    TSpec: EthSpec,
{
    /// A response has been sent, pending writing.
    ResponsePendingSend {
        /// The substream used to send the response
        substream: InboundFramed<NegotiatedSubstream, TSpec>,
        /// The message that is attempting to be sent.
        message: RPCCodedResponse<TSpec>,
        /// Whether a stream termination is requested. If true the stream will be closed after
        /// this send. Otherwise it will transition to an idle state until a stream termination is
        /// requested or a timeout is reached.
        closing: bool,
    },
    /// A response has been sent, pending flush.
    ResponsePendingFlush {
        /// The substream used to send the response
        substream: InboundFramed<NegotiatedSubstream, TSpec>,
        /// Whether a stream termination is requested. If true the stream will be closed after
        /// this send. Otherwise it will transition to an idle state until a stream termination is
        /// requested or a timeout is reached.
        closing: bool,
    },
    /// The response stream is idle and awaiting input from the application to send more chunked
    /// responses.
    ResponseIdle(InboundFramed<NegotiatedSubstream, TSpec>),
    /// The substream is attempting to shutdown.
    Closing(InboundFramed<NegotiatedSubstream, TSpec>),
    /// Temporary state during processing
    Poisoned,
}

/// State of an outbound substream. Either waiting for a response, or in the process of sending.
pub enum OutboundSubstreamState<TSpec: EthSpec> {
    /// A request has been sent, and we are awaiting a response. This future is driven in the
    /// handler because GOODBYE requests can be handled and responses dropped instantly.
    RequestPendingResponse {
        /// The framed negotiated substream.
        substream: OutboundFramed<NegotiatedSubstream, TSpec>,
        /// Keeps track of the actual request sent.
        request: RPCRequest<TSpec>,
    },
    /// Closing an outbound substream>
    Closing(OutboundFramed<NegotiatedSubstream, TSpec>),
    /// Temporary state during processing
    Poisoned,
}

impl<TSpec> InboundSubstreamState<TSpec>
where
    TSpec: EthSpec,
{
    /// Moves the substream state to closing and informs the connected peer. The
    /// `queued_outbound_items` must be given as a parameter to add stream termination messages to
    /// the outbound queue.
    pub fn close(&mut self, outbound_queue: &mut Vec<RPCCodedResponse<TSpec>>) {
        // When terminating a stream, report the stream termination to the requesting user via
        // an RPC error
        let error = RPCCodedResponse::ServerError("Request timed out".into());

        // The stream termination type is irrelevant, this will terminate the
        // stream
        let stream_termination =
            RPCCodedResponse::StreamTermination(ResponseTermination::BlocksByRange);

        match std::mem::replace(self, InboundSubstreamState::Poisoned) {
            // if we are busy awaiting a send/flush add the termination to the queue
            InboundSubstreamState::ResponsePendingSend {
                substream,
                message,
                closing,
            } => {
                if !closing {
                    outbound_queue.push(error);
                    outbound_queue.push(stream_termination);
                }
                // if the stream is closing after the send, allow it to finish

                *self = InboundSubstreamState::ResponsePendingSend {
                    substream,
                    message,
                    closing,
                }
            }
            // if we are busy awaiting a send/flush add the termination to the queue
            InboundSubstreamState::ResponsePendingFlush { substream, closing } => {
                if !closing {
                    outbound_queue.push(error);
                    outbound_queue.push(stream_termination);
                }
                // if the stream is closing after the send, allow it to finish
                *self = InboundSubstreamState::ResponsePendingFlush { substream, closing }
            }
            InboundSubstreamState::ResponseIdle(substream) => {
                *self = InboundSubstreamState::ResponsePendingSend {
                    substream,
                    message: error,
                    closing: true,
                };
            }
            InboundSubstreamState::Closing(substream) => {
                // let the stream close
                *self = InboundSubstreamState::Closing(substream);
            }
            InboundSubstreamState::Poisoned => {
                unreachable!("Coding error: Timeout poisoned substream")
            }
        };
    }
}

impl<TSpec> RPCHandler<TSpec>
where
    TSpec: EthSpec,
{
    pub fn new(
        listen_protocol: SubstreamProtocol<RPCProtocol<TSpec>>,
        inactive_timeout: Duration,
        log: &slog::Logger,
    ) -> Self {
        RPCHandler {
            listen_protocol,
            pending_errors: Vec::new(),
            events_out: SmallVec::new(),
            dial_queue: SmallVec::new(),
            dial_negotiated: 0,
            queued_outbound_items: FnvHashMap::default(),
            inbound_substreams: FnvHashMap::default(),
            outbound_substreams: FnvHashMap::default(),
            inbound_substreams_delay: DelayQueue::new(),
            outbound_substreams_delay: DelayQueue::new(),
            current_inbound_substream_id: SubstreamId(0),
            current_outbound_substream_id: SubstreamId(0),
            max_dial_negotiated: 8,
            keep_alive: KeepAlive::Yes,
            inactive_timeout,
            outbound_io_error_retries: 0,
            log: log.clone(),
        }
    }

    /// Returns a reference to the listen protocol configuration.
    ///
    /// > **Note**: If you modify the protocol, modifications will only applies to future inbound
    /// >           substreams, not the ones already being negotiated.
    pub fn listen_protocol_ref(&self) -> &SubstreamProtocol<RPCProtocol<TSpec>> {
        &self.listen_protocol
    }

    /// Returns a mutable reference to the listen protocol configuration.
    ///
    /// > **Note**: If you modify the protocol, modifications will only apply to future inbound
    /// >           substreams, not the ones already being negotiated.
    pub fn listen_protocol_mut(&mut self) -> &mut SubstreamProtocol<RPCProtocol<TSpec>> {
        &mut self.listen_protocol
    }

    /// Opens an outbound substream with a request.
    fn send_request(&mut self, id: RequestId, req: RPCRequest<TSpec>) {
        self.dial_queue.push((id, req));
        self.update_keep_alive();
    }

    /// Updates the `KeepAlive` returned by `connection_keep_alive`.
    ///
    /// The handler stays alive as long as there are inbound/outbound substreams established and no
    /// items dialing/to be dialed. Otherwise it is given a grace period of inactivity of
    /// `self.inactive_timeout`.
    fn update_keep_alive(&mut self) {
        // Check that we don't have outbound items pending for dialing, nor dialing, nor
        // established. Also check that there are no established inbound substreams.
        let should_shutdown = self.dial_queue.is_empty()
            && self.dial_negotiated == 0
            && self.outbound_substreams.is_empty()
            && self.inbound_substreams.is_empty();

        if should_shutdown {
            self.keep_alive = KeepAlive::Until(Instant::now() + self.inactive_timeout)
        } else {
            self.keep_alive = KeepAlive::Yes
        }
    }
}

impl<TSpec> ProtocolsHandler for RPCHandler<TSpec>
where
    TSpec: EthSpec,
{
    type InEvent = RPCSend<TSpec>;
    type OutEvent = Result<RPCReceived<TSpec>, HandlerErr>;
    type Error = RPCError;
    type InboundProtocol = RPCProtocol<TSpec>;
    type OutboundProtocol = RPCRequest<TSpec>;
    type OutboundOpenInfo = (RequestId, RPCRequest<TSpec>); // Keep track of the id and the request

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.listen_protocol.clone()
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        substream: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
    ) {
        let (req, substream) = substream;
        // drop the stream
        if let RPCRequest::Goodbye(_) = req {
            self.events_out
                .push(RPCReceived::Request(self.current_inbound_substream_id, req));
            self.current_inbound_substream_id.0 += 1;
            return;
        }

        // New inbound request. Store the stream and tag the output.
        let delay_key = self.inbound_substreams_delay.insert(
            self.current_inbound_substream_id,
            Duration::from_secs(RESPONSE_TIMEOUT),
        );
        let awaiting_stream = InboundSubstreamState::ResponseIdle(substream);
        self.inbound_substreams.insert(
            self.current_inbound_substream_id,
            (awaiting_stream, Some(delay_key), req.protocol()),
        );

        self.events_out
            .push(RPCReceived::Request(self.current_inbound_substream_id, req));
        self.current_inbound_substream_id.0 += 1;
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        out: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        request_info: Self::OutboundOpenInfo,
    ) {
        self.dial_negotiated -= 1;

        // add the stream to substreams if we expect a response, otherwise drop the stream.
        let (id, request) = request_info;
        let expected_responses = request.expected_responses();
        if expected_responses > 0 {
            // new outbound request. Store the stream and tag the output.
            let delay_key = self.outbound_substreams_delay.insert(
                self.current_outbound_substream_id,
                Duration::from_secs(RESPONSE_TIMEOUT),
            );
            let proto = request.protocol();
            let awaiting_stream = OutboundSubstreamState::RequestPendingResponse {
                substream: out,
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
                crit!(self.log, "Duplicate outbound substream id"; "id" => format!("{:?}", self.current_outbound_substream_id));
            }
            self.current_outbound_substream_id.0 += 1;
        }

        self.update_keep_alive();
    }

    // NOTE: If the substream has closed due to inactivity, or the substream is in the
    // wrong state a response will fail silently.
    fn inject_event(&mut self, rpc_event: Self::InEvent) {
        match rpc_event {
            RPCSend::Request(id, req) => self.send_request(id, req),
            RPCSend::Response(inbound_id, response) => {
                // Variables indicating if the response is an error response or a multi-part
                // response
                let res_is_error = response.is_error();
                let res_is_multiple = response.multiple_responses();

                // check if the stream matching the response still exists
                let (substream_state, protocol) = match self.inbound_substreams.get_mut(&inbound_id)
                {
                    Some((substream_state, _, protocol)) => (substream_state, protocol),
                    None => {
                        warn!(self.log, "Stream has expired. Response not sent";
                            "response" => response.to_string(), "id" => inbound_id);
                        return;
                    }
                };

                // If the response we are sending is an error, report back for handling
                match response {
                    RPCCodedResponse::InvalidRequest(ref reason)
                    | RPCCodedResponse::ServerError(ref reason)
                    | RPCCodedResponse::Unknown(ref reason) => {
                        let code = &response
                            .error_code()
                            .expect("Error response should map to an error code");
                        let err = HandlerErr::Inbound {
                            id: inbound_id,
                            proto: *protocol,
                            error: RPCError::ErrorResponse(*code, reason.to_string()),
                        };
                        self.pending_errors.push(err);
                    }
                    _ => {} // not an error, continue.
                }

                match std::mem::replace(substream_state, InboundSubstreamState::Poisoned) {
                    InboundSubstreamState::ResponseIdle(substream) => {
                        // close the stream if there is no response
                        match response {
                            RPCCodedResponse::StreamTermination(_) => {
                                *substream_state = InboundSubstreamState::Closing(substream);
                            }
                            _ => {
                                // send the response
                                // if it's a single rpc request or an error, close the stream after
                                *substream_state = InboundSubstreamState::ResponsePendingSend {
                                    substream,
                                    message: response,
                                    closing: !res_is_multiple | res_is_error, // close if an error or we are not expecting more responses
                                };
                            }
                        }
                    }
                    InboundSubstreamState::ResponsePendingSend {
                        substream,
                        message,
                        closing,
                    } if res_is_multiple => {
                        // the stream is in use, add the request to a pending queue
                        self.queued_outbound_items
                            .entry(inbound_id)
                            .or_insert_with(Vec::new)
                            .push(response);

                        // return the state
                        *substream_state = InboundSubstreamState::ResponsePendingSend {
                            substream,
                            message,
                            closing,
                        };
                    }
                    InboundSubstreamState::ResponsePendingFlush { substream, closing }
                        if res_is_multiple =>
                    {
                        // the stream is in use, add the request to a pending queue
                        self.queued_outbound_items
                            .entry(inbound_id)
                            .or_insert_with(Vec::new)
                            .push(response);

                        // return the state
                        *substream_state =
                            InboundSubstreamState::ResponsePendingFlush { substream, closing };
                    }
                    InboundSubstreamState::Closing(substream) => {
                        *substream_state = InboundSubstreamState::Closing(substream);
                        debug!(self.log, "Response not sent. Stream is closing"; "response" => format!("{}",response));
                    }
                    InboundSubstreamState::ResponsePendingSend {
                        substream, message, ..
                    } => {
                        *substream_state = InboundSubstreamState::ResponsePendingSend {
                            substream,
                            message,
                            closing: true,
                        };
                        error!(
                            self.log,
                            "Attempted sending multiple responses to a single response request"
                        );
                    }
                    InboundSubstreamState::ResponsePendingFlush { substream, .. } => {
                        *substream_state = InboundSubstreamState::ResponsePendingFlush {
                            substream,
                            closing: true,
                        };
                        error!(
                            self.log,
                            "Attempted sending multiple responses to a single response request"
                        );
                    }
                    InboundSubstreamState::Poisoned => {
                        crit!(self.log, "Poisoned inbound substream");
                        unreachable!("Coding error: Poisoned substream");
                    }
                }
            }
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
        self.pending_errors.push(HandlerErr::Outbound {
            id,
            proto: req.protocol(),
            error,
        });
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
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
        // report failures
        if !self.pending_errors.is_empty() {
            let err_info = self.pending_errors.remove(0);
            return Poll::Ready(ProtocolsHandlerEvent::Custom(Err(err_info)));
        }

        // return any events that need to be reported
        if !self.events_out.is_empty() {
            return Poll::Ready(ProtocolsHandlerEvent::Custom(Ok(self.events_out.remove(0))));
        } else {
            self.events_out.shrink_to_fit();
        }

        // purge expired inbound substreams and send an error
        loop {
            match self.inbound_substreams_delay.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(inbound_id))) => {
                    // handle a stream timeout for various states
                    if let Some((substream_state, delay_key, protocol)) =
                        self.inbound_substreams.get_mut(inbound_id.get_ref())
                    {
                        // the delay has been removed
                        *delay_key = None;

                        self.pending_errors.push(HandlerErr::Inbound {
                            id: *inbound_id.get_ref(),
                            proto: *protocol,
                            error: RPCError::StreamTimeout,
                        });

                        let outbound_queue = self
                            .queued_outbound_items
                            .entry(inbound_id.into_inner())
                            .or_insert_with(Vec::new);
                        substream_state.close(outbound_queue);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    warn!(self.log, "Inbound substream poll failed"; "error" => format!("{:?}", e));
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
            match self.outbound_substreams_delay.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(outbound_id))) => {
                    if let Some(OutboundInfo { proto, req_id, .. }) =
                        self.outbound_substreams.remove(outbound_id.get_ref())
                    {
                        self.update_keep_alive();

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
                    warn!(self.log, "Outbound substream poll failed"; "error" => format!("{:?}", e));
                    return Poll::Ready(ProtocolsHandlerEvent::Close(RPCError::InternalError(
                        "Could not poll outbound stream timer",
                    )));
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }

        // drive inbound streams that need to be processed
        for request_id in self.inbound_substreams.keys().copied().collect::<Vec<_>>() {
            // Drain all queued items until all messages have been processed for this stream
            // TODO Improve this code logic
            let mut drive_stream_further = true;
            while drive_stream_further {
                drive_stream_further = false;
                match self.inbound_substreams.entry(request_id) {
                    Entry::Occupied(mut entry) => {
                        match std::mem::replace(
                            &mut entry.get_mut().0,
                            InboundSubstreamState::Poisoned,
                        ) {
                            InboundSubstreamState::ResponsePendingSend {
                                mut substream,
                                message,
                                closing,
                            } => {
                                match Sink::poll_ready(Pin::new(&mut substream), cx) {
                                    Poll::Ready(Ok(())) => {
                                        // stream is ready to send data
                                        match Sink::start_send(Pin::new(&mut substream), message) {
                                            Ok(()) => {
                                                // await flush
                                                entry.get_mut().0 =
                                                    InboundSubstreamState::ResponsePendingFlush {
                                                        substream,
                                                        closing,
                                                    };
                                                drive_stream_further = true;
                                            }
                                            Err(e) => {
                                                // error with sending in the codec
                                                warn!(self.log, "Error sending RPC message"; "error" => e.to_string());
                                                // keep connection with the peer and return the
                                                // stream to awaiting response if this message
                                                // wasn't closing the stream
                                                // TODO: Duplicate code
                                                if closing {
                                                    entry.get_mut().0 =
                                                        InboundSubstreamState::Closing(substream);
                                                    drive_stream_further = true;
                                                } else {
                                                    // check for queued chunks and update the stream
                                                    entry.get_mut().0 = apply_queued_responses(
                                                        substream,
                                                        &mut self
                                                            .queued_outbound_items
                                                            .get_mut(&request_id),
                                                        &mut drive_stream_further,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Poll::Ready(Err(e)) => {
                                        error!(self.log, "Outbound substream error while sending RPC message: {:?}", e);
                                        entry.remove();
                                        self.update_keep_alive();
                                        return Poll::Ready(ProtocolsHandlerEvent::Close(e));
                                    }
                                    Poll::Pending => {
                                        // the stream is not yet ready, continue waiting
                                        entry.get_mut().0 =
                                            InboundSubstreamState::ResponsePendingSend {
                                                substream,
                                                message,
                                                closing,
                                            };
                                    }
                                }
                            }
                            InboundSubstreamState::ResponsePendingFlush {
                                mut substream,
                                closing,
                            } => {
                                match Sink::poll_flush(Pin::new(&mut substream), cx) {
                                    Poll::Ready(Ok(())) => {
                                        // finished flushing
                                        // TODO: Duplicate code
                                        if closing {
                                            entry.get_mut().0 =
                                                InboundSubstreamState::Closing(substream);
                                            drive_stream_further = true;
                                        } else {
                                            // check for queued chunks and update the stream
                                            entry.get_mut().0 = apply_queued_responses(
                                                substream,
                                                &mut self
                                                    .queued_outbound_items
                                                    .get_mut(&request_id),
                                                &mut drive_stream_further,
                                            );
                                        }
                                    }
                                    Poll::Ready(Err(e)) => {
                                        // error during flush
                                        trace!(self.log, "Error sending flushing RPC message"; "error" => e.to_string());
                                        // we drop the stream on error and inform the user, remove
                                        // any pending requests
                                        // TODO: Duplicate code
                                        if let Some(delay_key) = &entry.get().1 {
                                            self.inbound_substreams_delay.remove(delay_key);
                                        }
                                        self.queued_outbound_items.remove(&request_id);
                                        entry.remove();

                                        self.update_keep_alive();
                                    }
                                    Poll::Pending => {
                                        entry.get_mut().0 =
                                            InboundSubstreamState::ResponsePendingFlush {
                                                substream,
                                                closing,
                                            };
                                    }
                                }
                            }
                            InboundSubstreamState::ResponseIdle(substream) => {
                                entry.get_mut().0 = apply_queued_responses(
                                    substream,
                                    &mut self.queued_outbound_items.get_mut(&request_id),
                                    &mut drive_stream_further,
                                );
                            }
                            InboundSubstreamState::Closing(mut substream) => {
                                match Sink::poll_close(Pin::new(&mut substream), cx) {
                                    Poll::Ready(Ok(())) => {
                                        if let Some(delay_key) = &entry.get().1 {
                                            self.inbound_substreams_delay.remove(delay_key);
                                        }
                                        self.queued_outbound_items.remove(&request_id);
                                        entry.remove();

                                        self.update_keep_alive();
                                    } // drop the stream
                                    Poll::Ready(Err(e)) => {
                                        error!(self.log, "Error closing inbound stream"; "error" => e.to_string());
                                        // drop the stream anyway
                                        // TODO: Duplicate code
                                        if let Some(delay_key) = &entry.get().1 {
                                            self.inbound_substreams_delay.remove(delay_key);
                                        }
                                        self.queued_outbound_items.remove(&request_id);
                                        entry.remove();

                                        self.update_keep_alive();
                                    }
                                    Poll::Pending => {
                                        entry.get_mut().0 =
                                            InboundSubstreamState::Closing(substream);
                                    }
                                }
                            }
                            InboundSubstreamState::Poisoned => {
                                crit!(self.log, "Poisoned outbound substream");
                                unreachable!("Coding Error: Inbound Substream is poisoned");
                            }
                        }
                    }
                    Entry::Vacant(_) => unreachable!(),
                }
            }
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
                    mut substream,
                    request,
                } => match substream.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(response))) => {
                        if request.expected_responses() > 1 && !response.is_error() {
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
                            // either this is a single response request or we received an
                            // error only expect a single response, close the stream
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
                            RPCCodedResponse::InvalidRequest(ref r)
                            | RPCCodedResponse::ServerError(ref r)
                            | RPCCodedResponse::Unknown(ref r) => {
                                let code = response.error_code().expect(
                                    "Response indicating and error should map to an error code",
                                );
                                Err(HandlerErr::Outbound {
                                    id,
                                    proto,
                                    error: RPCError::ErrorResponse(code, r.to_string()),
                                })
                            }
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
                        let request_id = *&entry.get().req_id;
                        self.outbound_substreams_delay.remove(delay_key);
                        entry.remove_entry();
                        self.update_keep_alive();
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
                        self.update_keep_alive();
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
                            self.update_keep_alive();

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
            self.update_keep_alive();
            return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(req.clone()),
                info: (id, req),
            });
        }
        Poll::Pending
    }
}

// Check for new items to send to the peer and update the underlying stream
fn apply_queued_responses<TSpec: EthSpec>(
    substream: InboundFramed<NegotiatedSubstream, TSpec>,
    queued_outbound_items: &mut Option<&mut Vec<RPCCodedResponse<TSpec>>>,
    new_items_to_send: &mut bool,
) -> InboundSubstreamState<TSpec> {
    match queued_outbound_items {
        Some(ref mut queue) if !queue.is_empty() => {
            *new_items_to_send = true;
            // we have queued items
            match queue.remove(0) {
                RPCCodedResponse::StreamTermination(_) => {
                    // close the stream if this is a stream termination
                    InboundSubstreamState::Closing(substream)
                }
                chunk => InboundSubstreamState::ResponsePendingSend {
                    substream,
                    message: chunk,
                    closing: false,
                },
            }
        }
        _ => {
            // no items queued set to idle
            InboundSubstreamState::ResponseIdle(substream)
        }
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
