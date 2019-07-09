use super::protocol::{ProtocolId, RPCError, RPCProtocol, RPCRequest};
use super::RPCEvent;
use fnv::FnvHashMap;
use futures::prelude::*;
use libp2p::core::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use libp2p::core::upgrade::{self, InboundUpgrade, OutboundUpgrade, WriteOne};
use smallvec::SmallVec;
use std::time::{Duration, Instant};
use tokio_io::{AsyncRead, AsyncWrite};

/// The time (in seconds) before a substream that is awaiting a response times out.
pub const RESPONSE_TIMEOUT: u64 = 9;

/// Implementation of `ProtocolsHandler` for the RPC protocol.
pub struct RPCHandler<TSubstream> {
    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<RPCProtocol>,

    /// If `Some`, something bad happened and we should shut down the handler with an error.
    pending_error: Option<ProtocolsHandlerUpgrErr<RPCError>>,

    /// Queue of events to produce in `poll()`.
    events_out: SmallVec<[RPCEvent; 4]>,

    /// Queue of outbound substreams to open.
    dial_queue: SmallVec<[(usize, RPCRequest); 4]>,

    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,

    /// Map of current substreams awaiting a response to an RPC request.
    waiting_substreams: FnvHashMap<usize, SubstreamState<TSubstream>>,

    /// Sequential Id for waiting substreams.
    current_substream_id: usize,

    /// Maximum number of concurrent outbound substreams being opened. Value is never modified.
    max_dial_negotiated: u32,

    /// Value to return from `connection_keep_alive`.
    keep_alive: KeepAlive,

    /// After the given duration has elapsed, an inactive connection will shutdown.
    inactive_timeout: Duration,
}

/// State of an outbound substream. Either waiting for a response, or in the process of sending.
pub enum SubstreamState<TSubstream> {
    /// An outbound substream is waiting a response from the user.
    WaitingResponse {
        /// The negotiated substream.
        substream: upgrade::Negotiated<TSubstream>,
        /// The protocol that was negotiated.
        negotiated_protocol: ProtocolId,
        /// The time until we close the substream.
        timeout: Instant,
    },
    /// A response has been sent and we are waiting for the stream to close.
    PendingWrite(WriteOne<upgrade::Negotiated<TSubstream>, Vec<u8>>),
}

impl<TSubstream> RPCHandler<TSubstream> {
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
            current_substream_id: 0,
            max_dial_negotiated: 8,
            keep_alive: KeepAlive::Yes,
            inactive_timeout,
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

    /// Opens an outbound substream with `upgrade`.
    #[inline]
    pub fn send_request(&mut self, request_id: usize, upgrade: RPCRequest) {
        self.keep_alive = KeepAlive::Yes;
        self.dial_queue.push((request_id, upgrade));
    }
}

impl<TSubstream> Default for RPCHandler<TSubstream> {
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
    type OutboundOpenInfo = usize; // request_id

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.listen_protocol.clone()
    }

    #[inline]
    fn inject_fully_negotiated_inbound(
        &mut self,
        out: <RPCProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        let (substream, req, negotiated_protocol) = out;
        // drop the stream and return a 0 id for goodbye "requests"
        if let r @ RPCRequest::Goodbye(_) = req {
            self.events_out.push(RPCEvent::Request(0, r));
            return;
        }

        // New inbound request. Store the stream and tag the output.
        let awaiting_stream = SubstreamState::WaitingResponse {
            substream,
            negotiated_protocol,
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
        request_id: Self::OutboundOpenInfo,
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

        self.events_out.push(RPCEvent::Response(request_id, out));
    }

    // Note: If the substream has closed due to inactivity, or the substream is in the
    // wrong state a response will fail silently.
    #[inline]
    fn inject_event(&mut self, rpc_event: Self::InEvent) {
        match rpc_event {
            RPCEvent::Request(rpc_id, req) => self.send_request(rpc_id, req),
            RPCEvent::Response(rpc_id, res) => {
                // check if the stream matching the response still exists
                if let Some(waiting_stream) = self.waiting_substreams.get_mut(&rpc_id) {
                    // only send one response per stream. This must be in the waiting state.
                    if let SubstreamState::WaitingResponse {
                        substream,
                        negotiated_protocol,
                        ..
                    } = *waiting_stream
                    {
                        *waiting_stream = SubstreamState::PendingWrite(upgrade::write_one(
                            substream,
                            res.encode(negotiated_protocol)
                                .expect("Response should always be encodeable"),
                        ));
                    }
                }
            }
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
        dbg!(error);
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
            return Err(err);
        }

        // prioritise sending responses for waiting substreams
        self.waiting_substreams.retain(|_k, mut waiting_stream| {
            match waiting_stream {
                SubstreamState::PendingWrite(write_one) => {
                    match write_one.poll() {
                        Ok(Async::Ready(_socket)) => false,
                        Ok(Async::NotReady) => true,
                        Err(_e) => {
                            //TODO: Add logging
                            // throw away streams that error
                            false
                        }
                    }
                }
                SubstreamState::WaitingResponse { timeout, .. } => {
                    if Instant::now() > *timeout {
                        false
                    } else {
                        true
                    }
                }
            }
        });

        if !self.events_out.is_empty() {
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                self.events_out.remove(0),
            )));
        } else {
            self.events_out.shrink_to_fit();
        }

        // establish outbound substreams
        if !self.dial_queue.is_empty() {
            if self.dial_negotiated < self.max_dial_negotiated {
                self.dial_negotiated += 1;
                let (request_id, req) = self.dial_queue.remove(0);
                return Ok(Async::Ready(
                    ProtocolsHandlerEvent::OutboundSubstreamRequest {
                        protocol: SubstreamProtocol::new(req),
                        info: request_id,
                    },
                ));
            }
        } else {
            self.dial_queue.shrink_to_fit();
        }
        Ok(Async::NotReady)
    }
}
