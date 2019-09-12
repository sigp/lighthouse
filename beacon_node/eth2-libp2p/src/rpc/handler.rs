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
use smallvec::SmallVec;
use std::time::{Duration, Instant};
use tokio_io::{AsyncRead, AsyncWrite};

//TODO: Implement close() on the substream types to improve the poll code.
//TODO: Implement check_timeout() on the substream types

/// The time (in seconds) before a substream that is awaiting a response from the user times out.
pub const RESPONSE_TIMEOUT: u64 = 10;

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

    /// Map of current substreams awaiting a response to an RPC request.
    waiting_substreams: FnvHashMap<RequestId, WaitingResponse<TSubstream>>,

    /// List of single outbound substreams that need to be driven to completion.
    substreams: Vec<SubstreamState<TSubstream>>,

    /// Map of outbound items that are queued as the stream processes them.
    queued_outbound_items: FnvHashMap<RequestId, Vec<Option<RPCErrorResponse>>>,

    /// Sequential Id for waiting substreams.
    current_substream_id: RequestId,

    /// Maximum number of concurrent outbound substreams being opened. Value is never modified.
    max_dial_negotiated: u32,

    /// Value to return from `connection_keep_alive`.
    keep_alive: KeepAlive,

    /// After the given duration has elapsed, an inactive connection will shutdown.
    inactive_timeout: Duration,

    /// Marker to pin the generic stream.
    _phantom: PhantomData<TSubstream>,
}

/// An outbound substream is waiting a response from the user.
struct WaitingResponse<TSubstream> {
    /// The framed negotiated substream.
    substream: InboundFramed<TSubstream>,
    /// The time when the substream is closed.
    timeout: Instant,
}

/// State of an outbound substream. Either waiting for a response, or in the process of sending.
pub enum SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// A response has been sent, pending writing and flush.
    ResponsePendingSend {
        /// The substream used to send the response
        substream: futures::sink::Send<InboundFramed<TSubstream>>,
        /// The request id associated with the response.
        request_id: RequestId,
        /// Whether a stream termination is requested. If true the stream will be closed after
        /// this send. Otherwise it will transition to an idle state until a stream termination is
        /// requested or a timeout is reached.
        closing: bool,
    },
    /// The response stream is idle and awaiting input from the application to send more chunked
    /// responses.
    ResponseIdle {
        /// The substream used to send the response
        substream: InboundFramed<TSubstream>,
        /// The id associated with the request.
        request_id: RequestId,
        /// A timeout for how long we keep idle streams for before closing the stream.
        timeout: Instant,
    },
    /// A request has been sent, and we are awaiting a response. This future is driven in the
    /// handler because GOODBYE requests can be handled and responses dropped instantly.
    RequestPendingResponse {
        /// The framed negotiated substream.
        substream: OutboundFramed<TSubstream>,
        /// Keeps track of the request id for the request.
        id: RequestId,
        /// Keeps track of the actual request sent.
        request: RPCRequest,
        /// The time  when the substream is closed.
        timeout: Instant,
    },
    ClosingOutbound(OutboundFramed<TSubstream>),
    ClosingInbound(InboundFramed<TSubstream>),
}

impl<TSubstream> RPCHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    pub fn new(
        listen_protocol: SubstreamProtocol<RPCProtocol>,
        inactive_timeout: Duration,
    ) -> Self {
        RPCHandler {
            listen_protocol,
            pending_error: None,
            events_out: SmallVec::new(),
            dial_queue: SmallVec::new(),
            dial_negotiated: 0,
            waiting_substreams: FnvHashMap::default(),
            queued_outbound_items: FnvHashMap::default(),
            substreams: Vec::new(),
            current_substream_id: 1,
            max_dial_negotiated: 8,
            keep_alive: KeepAlive::Yes,
            inactive_timeout,
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

impl<TSubstream> Default for RPCHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn default() -> Self {
        RPCHandler::new(SubstreamProtocol::new(RPCProtocol), Duration::from_secs(30))
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
            return;
        }

        // New inbound request. Store the stream and tag the output.
        let awaiting_stream = WaitingResponse {
            substream,
            timeout: Instant::now() + Duration::from_secs(RESPONSE_TIMEOUT),
        };
        self.waiting_substreams
            .insert(self.current_substream_id, awaiting_stream);

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
            && self.waiting_substreams.is_empty()
        {
            self.keep_alive = KeepAlive::Until(Instant::now() + self.inactive_timeout);
        } else {
            self.keep_alive = KeepAlive::Yes;
        }

        // add the stream to substreams if we expect a response, otherwise drop the stream.
        if let RPCEvent::Request(id, request) = rpc_event {
            if request.expect_response() {
                let awaiting_stream = SubstreamState::RequestPendingResponse {
                    substream: out,
                    id,
                    request,
                    timeout: Instant::now() + Duration::from_secs(RESPONSE_TIMEOUT),
                };

                self.substreams.push(awaiting_stream);
            }
        }
    }

    // Note: If the substream has closed due to inactivity, or the substream is in the
    // wrong state a response will fail silently.
    #[inline]
    fn inject_event(&mut self, rpc_event: Self::InEvent) {
        match rpc_event {
            RPCEvent::Request(_, _) => self.send_request(rpc_event),
            RPCEvent::Response(rpc_id, res) => {
                //TODO: Restructure the stream management for multiple chunks

                //All this logic is to prevent multiple channel sends. A generalised response could
                //be terminated if every response sent a None to terminate the stream.

                let res_is_multiple = res.multiple_responses();
                let res_end_of_stream = res.is_none();
                // and add data to them, until the stream is terminated.
                // check if the stream matching the response still exists
                if let Some(waiting_stream) = self.waiting_substreams.remove(&rpc_id) {
                    // Process the response stream. This must be in the waiting state.
                    // build the stream from the response
                    // If it's a single rpc request or an error, close the stream after
                    let res_is_error = res.is_error();
                    self.substreams.push(SubstreamState::ResponsePendingSend {
                        substream: waiting_stream.substream.send(res),
                        request_id: rpc_id,
                        closing: !res_is_multiple | res_is_error, // close if an error or we are not expecting more responses
                    });
                } else {
                    // It could be that this is a multiple response, so we add it to the queue
                    // of responses to send
                    if res_is_multiple {
                        // if end of stream apply to the queue
                        if res_end_of_stream {
                            (*self
                                .queued_outbound_items
                                .entry(rpc_id)
                                .or_insert_with(Vec::new))
                            .push(None);
                        } else {
                            // add the item to the queue
                            (*self
                                .queued_outbound_items
                                .entry(rpc_id)
                                .or_insert_with(Vec::new))
                            .push(Some(res));
                        }
                    }
                }
            }
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
            // TODO: Add a logger to the handler for trace output.
            dbg!(&err);
        }

        // return any events that need to be reported
        if !self.events_out.is_empty() {
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                self.events_out.remove(0),
            )));
        } else {
            self.events_out.shrink_to_fit();
        }

        // close any streams that have expired
        let expired_streams: Vec<RequestId> = self
            .waiting_substreams
            .iter()
            .filter(|(_id, waiting_stream)| Instant::now() >= waiting_stream.timeout)
            .map(|(id, _v)| id)
            .cloned()
            .collect();

        for expired_stream in &expired_streams {
            // closes all expired streams
            self.substreams.push(SubstreamState::ClosingInbound(
                self.waiting_substreams
                    .remove(expired_stream)
                    .expect("must exist")
                    .substream,
            ));
        }

        // drive streams that need to be processed
        for n in (0..self.substreams.len()).rev() {
            let stream = self.substreams.swap_remove(n);
            match stream {
                SubstreamState::ResponsePendingSend {
                    mut substream,
                    request_id,
                    closing,
                } => {
                    match substream.poll() {
                        Ok(Async::Ready(raw_substream)) => {
                            // completed the send

                            // close the stream if required
                            if closing {
                                self.substreams
                                    .push(SubstreamState::ClosingInbound(raw_substream));
                            } else {
                                // check for queued chunks and update the steam
                                update_chunked_stream(
                                    &mut self.substreams,
                                    raw_substream,
                                    request_id,
                                    &mut self.queued_outbound_items,
                                );
                            }
                        }
                        Ok(Async::NotReady) => {
                            self.substreams.push(SubstreamState::ResponsePendingSend {
                                substream,
                                request_id,
                                closing,
                            });
                        }
                        Err(e) => {
                            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                RPCEvent::Error(0, e),
                            )))
                        }
                    }
                }
                SubstreamState::ResponseIdle {
                    substream,
                    request_id,
                    timeout,
                } => {
                    // TODO: Verify poll gets called after updating the queue from inject_event
                    // if past the timeout, close the stream
                    if Instant::now() > timeout {
                        self.substreams
                            .push(SubstreamState::ClosingInbound(substream));
                    } else {
                        update_chunked_stream(
                            &mut self.substreams,
                            substream,
                            request_id,
                            &mut self.queued_outbound_items,
                        );
                    }
                }
                SubstreamState::RequestPendingResponse {
                    mut substream,
                    id,
                    request,
                    timeout,
                } => match substream.poll() {
                    Ok(Async::Ready(Some(response))) => {
                        if request.multiple_responses() {
                            self.substreams
                                .push(SubstreamState::RequestPendingResponse {
                                    substream,
                                    id,
                                    request,
                                    timeout: Instant::now() + Duration::from_secs(RESPONSE_TIMEOUT),
                                });
                        } else {
                            // only expect a single response, close the stream
                            self.substreams
                                .push(SubstreamState::ClosingOutbound(substream));
                            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                RPCEvent::Response(id, response),
                            )));
                        }
                    }
                    Ok(Async::Ready(None)) => {
                        // stream closed
                        // if we expected multiple streams send a stream termination,
                        // else report the stream terminating only.
                        if request.multiple_responses() {
                            // return and end of stream result
                            let response = {
                                let resp = match request {
                                    RPCRequest::BlocksByRange(_) => {
                                        RPCResponse::BlocksByRange(None)
                                    }
                                    RPCRequest::BlocksByRoot(_) => RPCResponse::BlocksByRoot(None),
                                    _ => unreachable!("Not multiple responses"),
                                };
                                RPCErrorResponse::Success(resp)
                            };

                            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                RPCEvent::Response(id, response),
                            )));
                        } // else we return an error, stream should not have closed early.
                        return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                            RPCEvent::Error(
                                id,
                                RPCError::Custom("Stream closed early. Empty response".into()),
                            ),
                        )));
                    }
                    Ok(Async::NotReady) => {
                        if Instant::now() < timeout {
                            self.substreams
                                .push(SubstreamState::RequestPendingResponse {
                                    substream,
                                    id,
                                    request,
                                    timeout,
                                });
                        } else {
                            // timed out, close the stream
                            self.substreams
                                .push(SubstreamState::ClosingOutbound(substream));
                        }
                    }
                    Err(e) => {
                        return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                            RPCEvent::Error(id, e),
                        )))
                    }
                },
                SubstreamState::ClosingInbound(mut substream) => match substream.close() {
                    Ok(Async::Ready(())) => {} // drop the stream
                    Ok(Async::NotReady) => self
                        .substreams
                        .push(SubstreamState::ClosingInbound(substream)),
                    Err(_) => {} // drop the stream
                },
                SubstreamState::ClosingOutbound(mut substream) => match substream.close() {
                    Ok(Async::Ready(())) => {} // drop the stream
                    Ok(Async::NotReady) => self
                        .substreams
                        .push(SubstreamState::ClosingOutbound(substream)),
                    Err(_) => {} // drop the stream
                },
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

// Check for new items to send to the peer
fn update_chunked_stream<TSubstream: AsyncRead + AsyncWrite>(
    substreams: &mut Vec<SubstreamState<TSubstream>>,
    raw_substream: InboundFramed<TSubstream>,
    request_id: RequestId,
    queued_outbound_items: &mut FnvHashMap<RequestId, Vec<Option<RPCErrorResponse>>>,
) {
    match queued_outbound_items.get_mut(&request_id) {
        Some(ref mut queue) if !queue.is_empty() => {
            // we have queued items
            match queue.remove(0) {
                Some(chunk) => substreams.push(SubstreamState::ResponsePendingSend {
                    substream: raw_substream.send(chunk),
                    request_id,
                    closing: false,
                }),
                // stream termination sent
                None => substreams.push(SubstreamState::ClosingInbound(raw_substream)),
            }
        }
        _ => {
            // no items queued set to idle
            substreams.push(SubstreamState::ResponseIdle {
                substream: raw_substream,
                request_id,
                timeout: Instant::now() + Duration::from_secs(RESPONSE_TIMEOUT),
            });
        }
    }
}
