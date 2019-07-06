
use libp2p::core::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr,
    SubstreamProtocol
};
use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade};
use futures::prelude::*;
use smallvec::SmallVec;
use std::{error, marker::PhantomData, time::Duration};
use tokio_io::{AsyncRead, AsyncWrite};
use wasm_timer::Instant;

/// The time (in seconds) before a substream that is awaiting a response times out.
pub const RESPONSE_TIMEOUT: u64 = 9;

/// Implementation of `ProtocolsHandler` for the RPC protocol.
pub struct RPCHandler<TSubstream, TSocket>

    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<RPCProtocol>,

    /// If `Some`, something bad happened and we should shut down the handler with an error.
    pending_error: Option<ProtocolsHandlerUpgrErr<RPCRequest::Error>>,

    /// Queue of events to produce in `poll()`.
    events_out: SmallVec<[TOutEvent; 4]>,

    /// Queue of outbound substreams to open.
    dial_queue: SmallVec<[TOutProto; 4]>,

    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,

    /// Map of current substreams awaiting a response to an RPC request.
    waiting_substreams: FnvHashMap<u64, WaitingStream<TSubstream>

    /// Sequential Id for waiting substreams.
    current_substream_id: usize,

    /// Maximum number of concurrent outbound substreams being opened. Value is never modified.
    max_dial_negotiated: u32,

    /// Value to return from `connection_keep_alive`.
    keep_alive: KeepAlive,

    /// After the given duration has elapsed, an inactive connection will shutdown.
    inactive_timeout: Duration,
}

struct WaitingStream<TSubstream> {
    stream: TSubstream,
    timeout: Duration,
}

impl<TSubstream>
    RPCHandler<TSubstream>
{
    pub fn new(
        listen_protocol: SubstreamProtocol<RPCProtocol>,
        inactive_timeout: Duration
    ) -> Self {
        RPCHandler {
            listen_protocol,
            pending_error: None,
            events_out: SmallVec::new(),
            dial_queue: SmallVec::new(),
            dial_negotiated: 0,
            waiting_substreams: FnvHashMap::default(),
            curent_substream_id: 0,
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
    pub fn listen_protocol_ref(&self) -> &SubstreamProtocol<TInProto> {
        &self.listen_protocol
    }

    /// Returns a mutable reference to the listen protocol configuration.
    ///
    /// > **Note**: If you modify the protocol, modifications will only applies to future inbound
    /// >           substreams, not the ones already being negotiated.
    pub fn listen_protocol_mut(&mut self) -> &mut SubstreamProtocol<TInProto> {
        &mut self.listen_protocol
    }

    /// Opens an outbound substream with `upgrade`.
    #[inline]
    pub fn send_request(&mut self, upgrade: RPCRequest) {
        self.keep_alive = KeepAlive::Yes;
        self.dial_queue.push(upgrade);
    }
}

impl<TSubstream> Default
    for RPCHandler<TSubstream>
{
    fn default() -> Self {
        RPCHandler::new(SubstreamProtocol::new(RPCProtocol), Duration::from_secs(10))
    }
}

impl<TSubstream> ProtocolsHandler
    for RPCHandler<TSubstream>
{
    type InEvent = RPCRequest;
    type OutEvent = RPCEvent;
    type Error = ProtocolsHandlerUpgrErr<RPCRequest::Error>;
    type Substream = TSubstream;
    type InboundProtocol = RPCProtocol;
    type OutboundProtocol = RPCRequest;
    type OutboundOpenInfo = ();

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.listen_protocol.clone()
    }

    #[inline]
    fn inject_fully_negotiated_inbound(
        &mut self,
        out: RPCProtocol::Output,
    ) {
        if !self.keep_alive.is_yes() {
            self.keep_alive = KeepAlive::Until(Instant::now() + self.inactive_timeout);
        }

       let (stream, req) = out; 
       // drop the stream and return a 0 id for goodbye "requests"
       if let req @ RPCRequest::Goodbye(_) = req {
           self.events_out.push(RPCEvent::Request(0, req));
           return;
       }

        // New inbound request. Store the stream and tag the output.
        let awaiting_stream = WaitingStream { stream, timeout: Instant::now() + Duration::from_secs(RESPONSE_TIMEOUT) };
        self.waiting_substreams.insert(self.current_substream_id, awaiting_stream);

        self.events_out.push(RPCEvent::Request(self.current_substream_id, req));
        self.current_substream_id += 1;
    }

    #[inline]
    fn inject_fully_negotiated_outbound(
        &mut self,
        out: RPCResponse,
        _: Self::OutboundOpenInfo,
    ) {
        self.dial_negotiated -= 1;

        if self.dial_negotiated == 0 && self.dial_queue.is_empty() {
            self.keep_alive = KeepAlive::Until(Instant::now() + self.inactive_timeout);
        }

        self.events_out.push(out.into());
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        self.send_request(event);
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
            return Err(err);
        }

        if !self.events_out.is_empty() {
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                self.events_out.remove(0),
            )));
        } else {
            self.events_out.shrink_to_fit();
        }

        if !self.dial_queue.is_empty() {
            if self.dial_negotiated < self.max_dial_negotiated {
                self.dial_negotiated += 1;
                return Ok(Async::Ready(
                    ProtocolsHandlerEvent::OutboundSubstreamRequest {
                        protocol: SubstreamProtocol::new(self.dial_queue.remove(0)),
                        info: (),
                    },
                ));
            }
        } else {
            self.dial_queue.shrink_to_fit();
        }

        Ok(Async::NotReady)
    }
}
