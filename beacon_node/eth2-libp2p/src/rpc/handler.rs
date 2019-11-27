use super::methods::{RPCErrorResponse, RPCResponse, RequestId};
use super::protocol::{RPCError, RPCProtocol, RPCRequest};
use super::RPCEvent;
use crate::rpc::protocol::{InboundFramed, OutboundFramed};
use core::marker::PhantomData;
use fnv::FnvHashMap;
use futures::prelude::*;
use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade};
use libp2p::swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use slog::{crit, debug, error, trace, warn};
use smallvec::SmallVec;
use std::collections::hash_map::Entry;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::{delay_queue, DelayQueue};

//TODO: Implement close() on the substream types to improve the poll code.
//TODO: Implement check_timeout() on the substream types

/// The time (in seconds) before a substream that is awaiting a response from the user times out.
pub const RESPONSE_TIMEOUT: u64 = 10;

/// Inbound requests are given a sequential `RequestId` to keep track of.
type InboundRequestId = RequestId;
/// Outbound requests are associated with an id that is given by the application that sent the
/// request.
type OutboundRequestId = RequestId;

/// Implementation of `ProtocolsHandler` for the RPC protocol.
pub struct RPCHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<RPCProtocol>,

    /// If `Some`, something bad happened and we should shut down the handler with an error.
    pending_error: Option<ProtocolsHandlerUpgrErr<RPCError>>,

    /// Queue of events to produce in `poll()`.
    events_out: SmallVec<[RPCEvent; 4]>,

    /// Queue of outbound substreams to open.
    dial_queue: SmallVec<[RPCEvent; 4]>,

    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,

    /// Current inbound substreams awaiting processing.
    inbound_substreams:
        FnvHashMap<InboundRequestId, (InboundSubstreamState<TSubstream>, delay_queue::Key)>,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    inbound_substreams_delay: DelayQueue<InboundRequestId>,

    /// Map of outbound substreams that need to be driven to completion. The `RequestId` is
    /// maintained by the application sending the request.
    outbound_substreams:
        FnvHashMap<OutboundRequestId, (OutboundSubstreamState<TSubstream>, delay_queue::Key)>,

    /// Inbound substream `DelayQueue` which keeps track of when an inbound substream will timeout.
    outbound_substreams_delay: DelayQueue<OutboundRequestId>,

    /// Map of outbound items that are queued as the stream processes them.
    queued_outbound_items: FnvHashMap<RequestId, Vec<RPCErrorResponse>>,

    /// Sequential Id for waiting substreams.
    current_substream_id: RequestId,

    /// Maximum number of concurrent outbound substreams being opened. Value is never modified.
    max_dial_negotiated: u32,

    /// Value to return from `connection_keep_alive`.
    keep_alive: KeepAlive,

    /// After the given duration has elapsed, an inactive connection will shutdown.
    inactive_timeout: Duration,

    /// Logger for handling RPC streams
    log: slog::Logger,

    /// Marker to pin the generic stream.
    _phantom: PhantomData<TSubstream>,
}

/// State of an outbound substream. Either waiting for a response, or in the process of sending.
pub enum InboundSubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// A response has been sent, pending writing and flush.
    ResponsePendingSend {
        /// The substream used to send the response
        substream: futures::sink::Send<InboundFramed<TSubstream>>,
        /// Whether a stream termination is requested. If true the stream will be closed after
        /// this send. Otherwise it will transition to an idle state until a stream termination is
        /// requested or a timeout is reached.
        closing: bool,
    },
    /// The response stream is idle and awaiting input from the application to send more chunked
    /// responses.
    ResponseIdle(InboundFramed<TSubstream>),
    /// The substream is attempting to shutdown.
    Closing(InboundFramed<TSubstream>),
    /// Temporary state during processing
    Poisoned,
}

pub enum OutboundSubstreamState<TSubstream> {
    /// A request has been sent, and we are awaiting a response. This future is driven in the
    /// handler because GOODBYE requests can be handled and responses dropped instantly.
    RequestPendingResponse {
        /// The framed negotiated substream.
        substream: OutboundFramed<TSubstream>,
        /// Keeps track of the actual request sent.
        request: RPCRequest,
    },
    /// Closing an outbound substream>
    Closing(OutboundFramed<TSubstream>),
    /// Temporary state during processing
    Poisoned,
}

impl<TSubstream> RPCHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    pub fn new(
        listen_protocol: SubstreamProtocol<RPCProtocol>,
        inactive_timeout: Duration,
        log: &slog::Logger,
    ) -> Self {
        RPCHandler {
            listen_protocol,
            pending_error: None,
            events_out: SmallVec::new(),
            dial_queue: SmallVec::new(),
            dial_negotiated: 0,
            queued_outbound_items: FnvHashMap::default(),
            inbound_substreams: FnvHashMap::default(),
            outbound_substreams: FnvHashMap::default(),
            inbound_substreams_delay: DelayQueue::new(),
            outbound_substreams_delay: DelayQueue::new(),
            current_substream_id: 1,
            max_dial_negotiated: 8,
            keep_alive: KeepAlive::Yes,
            inactive_timeout,
            log: log.clone(),
            _phantom: PhantomData,
        }
    }

    /// Returns the number of pending requests.
    pub fn pending_requests(&self) -> u32 {
        self.dial_negotiated + self.dial_queue.len() as u32
    }

    /// Returns a reference to the listen protocol configuration.
    ///
    /// > **Note**: If you modify the protocol, modifications will only applies to future inbound
    /// >           substreams, not the ones already being negotiated.
    pub fn listen_protocol_ref(&self) -> &SubstreamProtocol<RPCProtocol> {
        &self.listen_protocol
    }

    /// Returns a mutable reference to the listen protocol configuration.
    ///
    /// > **Note**: If you modify the protocol, modifications will only applies to future inbound
    /// >           substreams, not the ones already being negotiated.
    pub fn listen_protocol_mut(&mut self) -> &mut SubstreamProtocol<RPCProtocol> {
        &mut self.listen_protocol
    }

    /// Opens an outbound substream with a request.
    #[inline]
    pub fn send_request(&mut self, rpc_event: RPCEvent) {
        self.keep_alive = KeepAlive::Yes;

        self.dial_queue.push(rpc_event);
    }
}

impl<TSubstream> ProtocolsHandler for RPCHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type InEvent = RPCEvent;
    type OutEvent = RPCEvent;
    type Error = ProtocolsHandlerUpgrErr<RPCError>;
    type Substream = TSubstream;
    type InboundProtocol = RPCProtocol;
    type OutboundProtocol = RPCRequest;
    type OutboundOpenInfo = RPCEvent; // Keep track of the id and the request

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.listen_protocol.clone()
    }

    #[inline]
    fn inject_fully_negotiated_inbound(
        &mut self,
        out: <RPCProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        let (req, substream) = out;
        // drop the stream and return a 0 id for goodbye "requests"
        if let r @ RPCRequest::Goodbye(_) = req {
            self.events_out.push(RPCEvent::Request(0, r));
            warn!(self.log, "Goodbye Received");
            return;
        }

        // New inbound request. Store the stream and tag the output.
        let delay_key = self.inbound_substreams_delay.insert(
            self.current_substream_id,
            Duration::from_secs(RESPONSE_TIMEOUT),
        );
        let awaiting_stream = InboundSubstreamState::ResponseIdle(substream);
        self.inbound_substreams
            .insert(self.current_substream_id, (awaiting_stream, delay_key));

        self.events_out
            .push(RPCEvent::Request(self.current_substream_id, req));
        self.current_substream_id += 1;
    }

    #[inline]
    fn inject_fully_negotiated_outbound(
        &mut self,
        out: <RPCRequest as OutboundUpgrade<TSubstream>>::Output,
        rpc_event: Self::OutboundOpenInfo,
    ) {
        self.dial_negotiated -= 1;

        if self.dial_negotiated == 0
            && self.dial_queue.is_empty()
            && self.outbound_substreams.is_empty()
        {
            self.keep_alive = KeepAlive::Until(Instant::now() + self.inactive_timeout);
        } else {
            self.keep_alive = KeepAlive::Yes;
        }

        // add the stream to substreams if we expect a response, otherwise drop the stream.
        match rpc_event {
            RPCEvent::Request(id, RPCRequest::Goodbye(_)) => {
                // notify the application layer, that a goodbye has been sent, so the application can
                // drop and remove the peer
                self.events_out.push(RPCEvent::Response(
                    id,
                    RPCErrorResponse::Success(RPCResponse::Goodbye),
                ));
            }
            RPCEvent::Request(id, request) if request.expect_response() => {
                // new outbound request. Store the stream and tag the output.
                let delay_key = self
                    .outbound_substreams_delay
                    .insert(id, Duration::from_secs(RESPONSE_TIMEOUT));
                let awaiting_stream = OutboundSubstreamState::RequestPendingResponse {
                    substream: out,
                    request,
                };
                self.outbound_substreams
                    .insert(id, (awaiting_stream, delay_key));
            }
            _ => { // a response is not expected, drop the stream for all other requests
            }
        }
    }

    // Note: If the substream has closed due to inactivity, or the substream is in the
    // wrong state a response will fail silently.
    #[inline]
    fn inject_event(&mut self, rpc_event: Self::InEvent) {
        match rpc_event {
            RPCEvent::Request(_, _) => self.send_request(rpc_event),
            RPCEvent::Response(rpc_id, response) => {
                // check if the stream matching the response still exists
                trace!(self.log, "Checking for outbound stream");

                // variables indicating if the response is an error response or a multi-part
                // response
                let res_is_error = response.is_error();
                let res_is_multiple = response.multiple_responses();

                match self.inbound_substreams.get_mut(&rpc_id) {
                    Some((substream_state, _)) => {
                        match std::mem::replace(substream_state, InboundSubstreamState::Poisoned) {
                            InboundSubstreamState::ResponseIdle(substream) => {
                                trace!(self.log, "Stream is idle, sending message"; "message" => format!("{}", response));
                                // close the stream if there is no response
                                if let RPCErrorResponse::StreamTermination(_) = response {
                                    trace!(self.log, "Stream termination sent. Ending the stream");
                                    *substream_state = InboundSubstreamState::Closing(substream);
                                } else {
                                    // send the response
                                    // if it's a single rpc request or an error, close the stream after
                                    *substream_state = InboundSubstreamState::ResponsePendingSend {
                                        substream: substream.send(response),
                                        closing: !res_is_multiple | res_is_error, // close if an error or we are not expecting more responses
                                    };
                                }
                            }
                            InboundSubstreamState::ResponsePendingSend { substream, closing }
                                if res_is_multiple =>
                            {
                                // the stream is in use, add the request to a pending queue
                                trace!(self.log, "Adding message to queue"; "message" => format!("{}", response));
                                (*self
                                    .queued_outbound_items
                                    .entry(rpc_id)
                                    .or_insert_with(Vec::new))
                                .push(response);

                                // return the state
                                *substream_state = InboundSubstreamState::ResponsePendingSend {
                                    substream,
                                    closing,
                                };
                            }
                            InboundSubstreamState::Closing(substream) => {
                                *substream_state = InboundSubstreamState::Closing(substream);
                                debug!(self.log, "Response not sent. Stream is closing"; "response" => format!("{}",response));
                            }
                            InboundSubstreamState::ResponsePendingSend { substream, .. } => {
                                *substream_state = InboundSubstreamState::ResponsePendingSend {
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
                        debug!(self.log, "Stream has expired. Response not sent"; "response" => format!("{}",response));
                    }
                };
            }
            // We do not send errors as responses
            RPCEvent::Error(_, _) => {}
        }
    }

    #[inline]
    fn inject_dial_upgrade_error(
        &mut self,
        _: Self::OutboundOpenInfo,
        error: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<Self::Substream>>::Error,
        >,
    ) {
        if self.pending_error.is_none() {
            self.pending_error = Some(error);
        }
    }

    #[inline]
    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
    }

    fn poll(
        &mut self,
    ) -> Poll<
        ProtocolsHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent>,
        Self::Error,
    > {
        if let Some(err) = self.pending_error.take() {
            // Returning an error here will result in dropping any peer that doesn't support any of
            // the RPC protocols. For our immediate purposes we permit this and simply log that an
            // upgrade was not supported.
            warn!(self.log,"RPC Protocol was not supported"; "Error" => format!("{}", err));
        }

        // return any events that need to be reported
        if !self.events_out.is_empty() {
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                self.events_out.remove(0),
            )));
        } else {
            self.events_out.shrink_to_fit();
        }

        // purge expired inbound substreams
        while let Async::Ready(Some(stream_id)) = self
            .inbound_substreams_delay
            .poll()
            .map_err(|_| ProtocolsHandlerUpgrErr::Timer)?
        {
            trace!(self.log, "Closing expired inbound stream");
            self.inbound_substreams.remove(stream_id.get_ref());
        }

        // purge expired outbound substreams
        while let Async::Ready(Some(stream_id)) = self
            .outbound_substreams_delay
            .poll()
            .map_err(|_| ProtocolsHandlerUpgrErr::Timer)?
        {
            trace!(self.log, "Closing expired outbound stream");
            self.outbound_substreams.remove(stream_id.get_ref());
        }

        // drive inbound streams that need to be processed
        for request_id in self.inbound_substreams.keys().copied().collect::<Vec<_>>() {
            // Drain all queued items until all messages have been processed for this stream
            // TODO Improve this code logic
            let mut new_items_to_send = true;
            while new_items_to_send == true {
                new_items_to_send = false;
                match self.inbound_substreams.entry(request_id) {
                    Entry::Occupied(mut entry) => {
                        match std::mem::replace(
                            &mut entry.get_mut().0,
                            InboundSubstreamState::Poisoned,
                        ) {
                            InboundSubstreamState::ResponsePendingSend {
                                mut substream,
                                closing,
                            } => {
                                match substream.poll() {
                                    Ok(Async::Ready(raw_substream)) => {
                                        // completed the send
                                        trace!(self.log, "RPC message sent");

                                        // close the stream if required
                                        if closing {
                                            entry.get_mut().0 =
                                                InboundSubstreamState::Closing(raw_substream)
                                        } else {
                                            // check for queued chunks and update the stream
                                            trace!(self.log, "Checking for queued items");
                                            entry.get_mut().0 = apply_queued_responses(
                                                raw_substream,
                                                &mut self
                                                    .queued_outbound_items
                                                    .get_mut(&request_id),
                                                &mut new_items_to_send,
                                            );
                                        }
                                    }
                                    Ok(Async::NotReady) => {
                                        entry.get_mut().0 =
                                            InboundSubstreamState::ResponsePendingSend {
                                                substream,
                                                closing,
                                            };
                                    }
                                    Err(e) => {
                                        let delay_key = &entry.get().1;
                                        self.inbound_substreams_delay.remove(delay_key);
                                        entry.remove_entry();
                                        return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                            RPCEvent::Error(0, e),
                                        )));
                                    }
                                };
                            }
                            InboundSubstreamState::ResponseIdle(substream) => {
                                trace!(self.log, "Idle stream searching queue");
                                entry.get_mut().0 = apply_queued_responses(
                                    substream,
                                    &mut self.queued_outbound_items.get_mut(&request_id),
                                    &mut new_items_to_send,
                                );
                            }
                            InboundSubstreamState::Closing(mut substream) => {
                                match substream.close() {
                                    Ok(Async::Ready(())) | Err(_) => {
                                        trace!(self.log, "Inbound stream dropped");
                                        let delay_key = &entry.get().1;
                                        self.queued_outbound_items.remove(&request_id);
                                        self.inbound_substreams_delay.remove(delay_key);
                                        entry.remove();
                                    } // drop the stream
                                    Ok(Async::NotReady) => {
                                        entry.get_mut().0 =
                                            InboundSubstreamState::Closing(substream);
                                    }
                                }
                            }
                            InboundSubstreamState::Poisoned => {
                                crit!(self.log, "Poisoned outbound substream");
                                unreachable!("Coding Error: Inbound Substream is poisoned");
                            }
                        };
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
                        } => match substream.poll() {
                            Ok(Async::Ready(Some(response))) => {
                                trace!(self.log, "Message received"; "message" => format!("{}", response));
                                if request.multiple_responses() {
                                    entry.get_mut().0 =
                                        OutboundSubstreamState::RequestPendingResponse {
                                            substream,
                                            request: request,
                                        };
                                    let delay_key = &entry.get().1;
                                    self.outbound_substreams_delay
                                        .reset(delay_key, Duration::from_secs(RESPONSE_TIMEOUT));
                                } else {
                                    trace!(self.log, "Closing single stream request");
                                    // only expect a single response, close the stream
                                    entry.get_mut().0 = OutboundSubstreamState::Closing(substream);
                                }
                                return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                    RPCEvent::Response(request_id, response),
                                )));
                            }
                            Ok(Async::Ready(None)) => {
                                // stream closed
                                // if we expected multiple streams send a stream termination,
                                // else report the stream terminating only.
                                trace!(self.log, "RPC Response - stream closed by remote");
                                // drop the stream
                                let delay_key = &entry.get().1;
                                self.outbound_substreams_delay.remove(delay_key);
                                entry.remove_entry();
                                // notify the application error
                                if request.multiple_responses() {
                                    // return an end of stream result
                                    return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                        RPCEvent::Response(
                                            request_id,
                                            RPCErrorResponse::StreamTermination(
                                                request.stream_termination(),
                                            ),
                                        ),
                                    )));
                                } // else we return an error, stream should not have closed early.
                                return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                    RPCEvent::Error(
                                        request_id,
                                        RPCError::Custom(
                                            "Stream closed early. Empty response".into(),
                                        ),
                                    ),
                                )));
                            }
                            Ok(Async::NotReady) => {
                                entry.get_mut().0 = OutboundSubstreamState::RequestPendingResponse {
                                    substream,
                                    request,
                                }
                            }
                            Err(e) => {
                                // drop the stream
                                let delay_key = &entry.get().1;
                                self.outbound_substreams_delay.remove(delay_key);
                                entry.remove_entry();
                                return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                    RPCEvent::Error(request_id, e),
                                )));
                            }
                        },
                        OutboundSubstreamState::Closing(mut substream) => match substream.close() {
                            Ok(Async::Ready(())) | Err(_) => {
                                trace!(self.log, "Outbound stream dropped");
                                // drop the stream
                                let delay_key = &entry.get().1;
                                self.outbound_substreams_delay.remove(delay_key);
                                entry.remove_entry();
                            }
                            Ok(Async::NotReady) => {
                                entry.get_mut().0 = OutboundSubstreamState::Closing(substream);
                            }
                        },
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
        if !self.dial_queue.is_empty() {
            if self.dial_negotiated < self.max_dial_negotiated {
                self.dial_negotiated += 1;
                let rpc_event = self.dial_queue.remove(0);
                if let RPCEvent::Request(id, req) = rpc_event {
                    return Ok(Async::Ready(
                        ProtocolsHandlerEvent::OutboundSubstreamRequest {
                            protocol: SubstreamProtocol::new(req.clone()),
                            info: RPCEvent::Request(id, req),
                        },
                    ));
                }
            }
        } else {
            self.dial_queue.shrink_to_fit();
        }
        Ok(Async::NotReady)
    }
}

// Check for new items to send to the peer and update the underlying stream
fn apply_queued_responses<TSubstream: AsyncRead + AsyncWrite>(
    raw_substream: InboundFramed<TSubstream>,
    queued_outbound_items: &mut Option<&mut Vec<RPCErrorResponse>>,
    new_items_to_send: &mut bool,
) -> InboundSubstreamState<TSubstream> {
    match queued_outbound_items {
        Some(ref mut queue) if !queue.is_empty() => {
            *new_items_to_send = true;
            // we have queued items
            match queue.remove(0) {
                RPCErrorResponse::StreamTermination(_) => {
                    // close the stream if this is a stream termination
                    InboundSubstreamState::Closing(raw_substream)
                }
                chunk => InboundSubstreamState::ResponsePendingSend {
                    substream: raw_substream.send(chunk),
                    closing: false,
                },
            }
        }
        _ => {
            // no items queued set to idle
            InboundSubstreamState::ResponseIdle(raw_substream)
        }
    }
}
