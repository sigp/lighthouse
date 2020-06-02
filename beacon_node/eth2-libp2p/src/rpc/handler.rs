#![allow(clippy::type_complexity)]
#![allow(clippy::cognitive_complexity)]

use super::methods::{RPCCodedResponse, RequestId, ResponseTermination};
use super::protocol::{Protocol, RPCError, RPCProtocol, RPCRequest};
use super::RPCEvent;
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

/// Inbound requests are given a sequential `RequestId` to keep track of. All inbound streams are
/// identified by their substream ID which is identical to the RPC Id.
type InboundRequestId = RequestId;
/// Outbound requests are associated with an id that is given by the application that sent the
/// request.
type OutboundRequestId = RequestId;

/// Implementation of `ProtocolsHandler` for the RPC protocol.
pub struct RPCHandler<TSpec>
where
    TSpec: EthSpec,
{
    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<RPCProtocol<TSpec>>,

    /// If something bad happened and we should shut down the handler with an error.
    pending_error: Vec<(RequestId, Protocol, RPCError)>,

    /// Queue of events to produce in `poll()`.
    events_out: SmallVec<[RPCEvent<TSpec>; 4]>,

    /// Queue of outbound substreams to open.
    dial_queue: SmallVec<[(RequestId, RPCRequest<TSpec>); 4]>,

    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,

    /// Current inbound substreams awaiting processing.
    inbound_substreams: FnvHashMap<
        InboundRequestId,
        (
            InboundSubstreamState<TSpec>,
            Option<delay_queue::Key>,
            Protocol,
        ),
    >,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    inbound_substreams_delay: DelayQueue<InboundRequestId>,

    /// Map of outbound substreams that need to be driven to completion. The `RequestId` is
    /// maintained by the application sending the request.
    /// For Responses with multiple expected response chunks a counter is added to be able to terminate the stream when the expected number has been received
    outbound_substreams: FnvHashMap<
        OutboundRequestId,
        (
            OutboundSubstreamState<TSpec>,
            delay_queue::Key,
            Protocol,
            Option<u64>,
        ),
    >,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    outbound_substreams_delay: DelayQueue<OutboundRequestId>,

    /// Map of outbound items that are queued as the stream processes them.
    queued_outbound_items: FnvHashMap<RequestId, Vec<RPCCodedResponse<TSpec>>>,

    /// Sequential ID for waiting substreams. For inbound substreams, this is also the inbound request ID.
    current_inbound_substream_id: RequestId,

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
                    substream: substream,
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
            pending_error: Vec::new(),
            events_out: SmallVec::new(),
            dial_queue: SmallVec::new(),
            dial_negotiated: 0,
            queued_outbound_items: FnvHashMap::default(),
            inbound_substreams: FnvHashMap::default(),
            outbound_substreams: FnvHashMap::default(),
            inbound_substreams_delay: DelayQueue::new(),
            outbound_substreams_delay: DelayQueue::new(),
            current_inbound_substream_id: 1,
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
    type InEvent = RPCEvent<TSpec>;
    type OutEvent = RPCEvent<TSpec>;
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
        // drop the stream and return a 0 id for goodbye "requests"
        if let r @ RPCRequest::Goodbye(_) = req {
            self.events_out.push(RPCEvent::Request(0, r));
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
            .push(RPCEvent::Request(self.current_inbound_substream_id, req));
        self.current_inbound_substream_id += 1;
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        out: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        request_info: Self::OutboundOpenInfo,
    ) {
        self.dial_negotiated -= 1;

        // add the stream to substreams if we expect a response, otherwise drop the stream.
        let (mut id, request) = request_info;
        if request.expect_response() {
            // outbound requests can be sent from various aspects of lighthouse which don't
            // track request ids. In the future these will be flagged as None, currently they
            // are flagged as 0. These can overlap. In this case, we pick the highest request
            // Id available
            if id == 0 && self.outbound_substreams.get(&id).is_some() {
                // have duplicate outbound request with no id. Pick one that will not collide
                let mut new_id = std::usize::MAX;
                while self.outbound_substreams.get(&new_id).is_some() {
                    // panic all outbound substreams are full
                    new_id -= 1;
                }
                trace!(self.log, "New outbound stream id created"; "id" => new_id);
                id = RequestId::from(new_id);
            }

            // new outbound request. Store the stream and tag the output.
            let delay_key = self
                .outbound_substreams_delay
                .insert(id, Duration::from_secs(RESPONSE_TIMEOUT));
            let protocol = request.protocol();
            let response_chunk_count = match request {
                RPCRequest::BlocksByRange(ref req) => Some(req.count),
                RPCRequest::BlocksByRoot(ref req) => Some(req.block_roots.len() as u64),
                _ => None, // Other requests do not have a known response chunk length,
            };
            let awaiting_stream = OutboundSubstreamState::RequestPendingResponse {
                substream: out,
                request: request,
            };
            if let Some(_) = self.outbound_substreams.insert(
                id,
                (awaiting_stream, delay_key, protocol, response_chunk_count),
            ) {
                crit!(self.log, "Duplicate outbound substream id"; "id" => format!("{:?}", id));
            }
        }

        self.update_keep_alive();
    }

    // NOTE: If the substream has closed due to inactivity, or the substream is in the
    // wrong state a response will fail silently.
    fn inject_event(&mut self, rpc_event: Self::InEvent) {
        match rpc_event {
            RPCEvent::Request(id, req) => self.send_request(id, req),
            RPCEvent::Response(rpc_id, response) => {
                // Variables indicating if the response is an error response or a multi-part
                // response
                let res_is_error = response.is_error();
                let res_is_multiple = response.multiple_responses();

                // check if the stream matching the response still exists
                match self.inbound_substreams.get_mut(&rpc_id) {
                    Some((substream_state, _, protocol)) => {
                        match std::mem::replace(substream_state, InboundSubstreamState::Poisoned) {
                            InboundSubstreamState::ResponseIdle(substream) => {
                                // close the stream if there is no response
                                match response {
                                    RPCCodedResponse::StreamTermination(_) => {
                                        //trace!(self.log, "Stream termination sent. Ending the stream");
                                        *substream_state =
                                            InboundSubstreamState::Closing(substream);
                                    }
                                    _ => {
                                        if let Some(error_code) = response.error_code() {
                                            self.pending_error.push((
                                                rpc_id,
                                                *protocol,
                                                RPCError::ErrorResponse(error_code),
                                            ));
                                        }
                                        // send the response
                                        // if it's a single rpc request or an error, close the stream after
                                        *substream_state =
                                            InboundSubstreamState::ResponsePendingSend {
                                                substream: substream,
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
                                    .entry(rpc_id)
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
                                    .entry(rpc_id)
                                    .or_insert_with(Vec::new)
                                    .push(response);

                                // return the state
                                *substream_state = InboundSubstreamState::ResponsePendingFlush {
                                    substream,
                                    closing,
                                };
                            }
                            InboundSubstreamState::Closing(substream) => {
                                *substream_state = InboundSubstreamState::Closing(substream);
                                debug!(self.log, "Response not sent. Stream is closing"; "response" => format!("{}",response));
                            }
                            InboundSubstreamState::ResponsePendingSend {
                                substream,
                                message,
                                ..
                            } => {
                                *substream_state = InboundSubstreamState::ResponsePendingSend {
                                    substream,
                                    message,
                                    closing: true,
                                };
                                error!(self.log, "Attempted sending multiple responses to a single response request");
                            }
                            InboundSubstreamState::ResponsePendingFlush { substream, .. } => {
                                *substream_state = InboundSubstreamState::ResponsePendingFlush {
                                    substream,
                                    closing: true,
                                };
                                error!(self.log, "Attempted sending multiple responses to a single response request");
                            }
                            InboundSubstreamState::Poisoned => {
                                crit!(self.log, "Poisoned inbound substream");
                                unreachable!("Coding error: Poisoned substream");
                            }
                        }
                    }
                    None => {
                        warn!(self.log, "Stream has expired. Response not sent"; "response" => response.to_string(), "id" => rpc_id);
                    }
                };
            }
            // We do not send errors as responses
            RPCEvent::Error(..) => {}
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
        let rpc_error = match error {
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
        self.pending_error.push((id, req.protocol(), rpc_error));
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
        if !self.pending_error.is_empty() {
            let (id, protocol, err) = self.pending_error.remove(0);
            return Poll::Ready(ProtocolsHandlerEvent::Custom(RPCEvent::Error(
                id, protocol, err,
            )));
        }

        // return any events that need to be reported
        if !self.events_out.is_empty() {
            return Poll::Ready(ProtocolsHandlerEvent::Custom(self.events_out.remove(0)));
        } else {
            self.events_out.shrink_to_fit();
        }

        // purge expired inbound substreams and send an error
        loop {
            match self.inbound_substreams_delay.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(stream_id))) => {
                    // handle a stream timeout for various states
                    if let Some((substream_state, delay_key, _)) =
                        self.inbound_substreams.get_mut(stream_id.get_ref())
                    {
                        // the delay has been removed
                        *delay_key = None;

                        let outbound_queue = self
                            .queued_outbound_items
                            .entry(stream_id.into_inner())
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
                Poll::Ready(Some(Ok(stream_id))) => {
                    if let Some((_id, _stream, protocol, _)) =
                        self.outbound_substreams.remove(stream_id.get_ref())
                    {
                        self.update_keep_alive();

                        // notify the user
                        return Poll::Ready(ProtocolsHandlerEvent::Custom(RPCEvent::Error(
                            *stream_id.get_ref(),
                            protocol,
                            RPCError::StreamTimeout,
                        )));
                    } else {
                        crit!(self.log, "timed out substream not in the books"; "stream_id" => stream_id.get_ref());
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
        for request_id in self.outbound_substreams.keys().copied().collect::<Vec<_>>() {
            match self.outbound_substreams.entry(request_id) {
                Entry::Occupied(mut entry) => {
                    match std::mem::replace(
                        &mut entry.get_mut().0,
                        OutboundSubstreamState::Poisoned,
                    ) {
                        OutboundSubstreamState::RequestPendingResponse {
                            mut substream,
                            request,
                        } => match substream.poll_next_unpin(cx) {
                            Poll::Ready(Some(Ok(response))) => {
                                if request.multiple_responses() && !response.is_error() {
                                    let substream_entry = entry.get_mut();
                                    let delay_key = &substream_entry.1;
                                    // chunks left after this one
                                    let remaining_chunks = substream_entry
                                        .3
                                        .map(|count| count.saturating_sub(1))
                                        .unwrap_or_else(|| 0);
                                    if remaining_chunks == 0 {
                                        // this is the last expected message, close the stream as all expected chunks have been received
                                        substream_entry.0 =
                                            OutboundSubstreamState::Closing(substream);
                                    } else {
                                        // If the response chunk was expected update the remaining number of chunks expected and reset the Timeout
                                        substream_entry.0 =
                                            OutboundSubstreamState::RequestPendingResponse {
                                                substream,
                                                request,
                                            };
                                        substream_entry.3 = Some(remaining_chunks);
                                        self.outbound_substreams_delay.reset(
                                            delay_key,
                                            Duration::from_secs(RESPONSE_TIMEOUT),
                                        );
                                    }
                                } else {
                                    // either this is a single response request or we received an
                                    // error
                                    // only expect a single response, close the stream
                                    entry.get_mut().0 = OutboundSubstreamState::Closing(substream);
                                }

                                return Poll::Ready(ProtocolsHandlerEvent::Custom(
                                    RPCEvent::Response(request_id, response),
                                ));
                            }
                            Poll::Ready(None) => {
                                // stream closed
                                // if we expected multiple streams send a stream termination,
                                // else report the stream terminating only.
                                //trace!(self.log, "RPC Response - stream closed by remote");
                                // drop the stream
                                let delay_key = &entry.get().1;
                                self.outbound_substreams_delay.remove(delay_key);
                                entry.remove_entry();

                                self.update_keep_alive();
                                // notify the application error
                                if request.multiple_responses() {
                                    // return an end of stream result
                                    return Poll::Ready(ProtocolsHandlerEvent::Custom(
                                        RPCEvent::Response(
                                            request_id,
                                            RPCCodedResponse::StreamTermination(
                                                request.stream_termination(),
                                            ),
                                        ),
                                    ));
                                } // else we return an error, stream should not have closed early.
                                return Poll::Ready(ProtocolsHandlerEvent::Custom(
                                    RPCEvent::Error(
                                        request_id,
                                        request.protocol(),
                                        RPCError::IncompleteStream,
                                    ),
                                ));
                            }
                            Poll::Pending => {
                                entry.get_mut().0 = OutboundSubstreamState::RequestPendingResponse {
                                    substream,
                                    request,
                                }
                            }
                            Poll::Ready(Some(Err(e))) => {
                                // drop the stream
                                let delay_key = &entry.get().1;
                                self.outbound_substreams_delay.remove(delay_key);
                                let protocol = entry.get().2;
                                entry.remove_entry();
                                self.update_keep_alive();
                                return Poll::Ready(ProtocolsHandlerEvent::Custom(
                                    RPCEvent::Error(request_id, protocol, e),
                                ));
                            }
                        },
                        OutboundSubstreamState::Closing(mut substream) => {
                            match Sink::poll_close(Pin::new(&mut substream), cx) {
                                Poll::Ready(_) => {
                                    // drop the stream and its corresponding timeout
                                    let delay_key = &entry.get().1;
                                    let protocol = entry.get().2;
                                    self.outbound_substreams_delay.remove(delay_key);
                                    entry.remove_entry();
                                    self.update_keep_alive();

                                    // report the stream termination to the user
                                    //
                                    // Streams can be terminated here if a responder tries to
                                    // continue sending responses beyond what we would expect. Here
                                    // we simply terminate the stream and report a stream
                                    // termination to the application
                                    match protocol {
                                        Protocol::BlocksByRange => {
                                            return Poll::Ready(ProtocolsHandlerEvent::Custom(
                                                RPCEvent::Response(
                                                    request_id,
                                                    RPCCodedResponse::StreamTermination(
                                                        ResponseTermination::BlocksByRange,
                                                    ),
                                                ),
                                            ));
                                        }
                                        Protocol::BlocksByRoot => {
                                            return Poll::Ready(ProtocolsHandlerEvent::Custom(
                                                RPCEvent::Response(
                                                    request_id,
                                                    RPCCodedResponse::StreamTermination(
                                                        ResponseTermination::BlocksByRoot,
                                                    ),
                                                ),
                                            ));
                                        }
                                        _ => {} // all other protocols are do not have multiple responses and we do not inform the user, we simply drop the stream.
                                    }
                                }
                                Poll::Pending => {
                                    entry.get_mut().0 = OutboundSubstreamState::Closing(substream);
                                }
                            }
                        }
                        OutboundSubstreamState::Poisoned => {
                            crit!(self.log, "Poisoned outbound substream");
                            unreachable!("Coding Error: Outbound substream is poisoned")
                        }
                    }
                }
                Entry::Vacant(_) => unreachable!(),
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
                    substream: substream,
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
