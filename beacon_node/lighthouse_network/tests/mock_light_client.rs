#![cfg(test)]
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::{Weak, Arc};
use std::task::{Poll, Context};
use std::pin::Pin;
use fnv::FnvHashMap;
use futures::future::BoxFuture;
use futures::{AsyncWrite, AsyncRead};
use libp2p::{OutboundUpgrade, InboundUpgrade};
use libp2p::core::{UpgradeInfo, UpgradeError};
use libp2p::core::upgrade::{NegotiationError, ProtocolError};
use lighthouse_network::rpc::methods::{Ping, RPCCodedResponse};
use lighthouse_network::rpc::{InboundRequest, ReqId, RPCMessage, SubstreamId, ProtocolId, Protocol, Version, Encoding, HandlerEvent, InboundInfo, HandlerState, StatusMessage, GoodbyeReason, LightClientBootstrapRequest, OutboundFramed, RPCError, OutboundCodec, BaseOutboundCodec, SSZSnappyOutboundCodec, RPCProtocol, RPCSend, HandlerErr, InboundState, RPCReceived, OutboundRequest};
use smallvec::SmallVec;
use tokio::runtime::Runtime;
use tokio_util::codec::Framed;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::time::{DelayQueue, delay_queue};
use types::{EthSpec, ForkContext};
use types::{
    ForkName, 
};
use slog::{o, debug, error};
use std::time::{Duration, Instant};
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction, ConnectionHandler, NegotiatedSubstream, ConnectionHandlerUpgrErr, KeepAlive, ConnectionHandlerEvent};
use futures::{AsyncWrite, AsyncRead};
use libp2p::swarm::handler::{
    SubstreamProtocol,
};
use futures::prelude::*;
use futures::{Sink, SinkExt};


use lighthouse_network::{NetworkEvent, EnrExt};
mod common;
use common::build_libp2p_instance;
use common::Libp2pInstance;

pub struct MockLibp2pLightClientInstance(MockLibP2PLightClientService, exit_future::Signal);

pub async fn build_mock_libp2p_light_client_instance() -> MockLibp2pLightClientInstance {
    unimplemented!()
}

#[allow(dead_code)]
pub async fn build_node_and_light_client(
    rt: Weak<Runtime>,
    log: &slog::Logger,
    fork_name: ForkName,
) -> (MockLibp2pLightClientInstance, Libp2pInstance) {
    let sender_log = log.new(o!("who" => "sender"));
    let receiver_log = log.new(o!("who" => "receiver"));

    // sender is light client
    let mut sender = build_mock_libp2p_light_client_instance().await;
    // receiver is full node
    let mut receiver = build_libp2p_instance(rt, vec![], receiver_log, fork_name).await;

    let receiver_multiaddr = receiver.local_enr().multiaddr()[1].clone();

    // let the two nodes set up listeners
    // TODO: use a differtent NetworkEvent for sender because it is a light client
    let sender_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(_) = sender.next_event().await {
                return;
            }
        }
    };
    let receiver_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(_) = receiver.next_event().await {
                return;
            }
        }
    };

    let joined = futures::future::join(sender_fut, receiver_fut);

    // wait for either both nodes to listen or a timeout
    tokio::select! {
        _  = tokio::time::sleep(Duration::from_millis(500)) => {}
        _ = joined => {}
    }

    // sender.dial_peer(peer_id);
    match sender.0.swarm.dial(receiver_multiaddr.clone()) {
        Ok(()) => {
            debug!(log, "Sender dialed receiver"; "address" => format!("{:?}", receiver_multiaddr))
        }
        Err(_) => error!(log, "Dialing failed"),
    };
    (sender, receiver)
}

//pub struct MockLibP2PLightClientService {
//    swarm: libp2p::swarm::Swarm<RPC>,
//}


pub struct RPC<Id: ReqId, TSpec: EthSpec> {
    /// Queue of events to be processed.
    events: Vec<NetworkBehaviourAction<RPCMessage<Id, TSpec>, MockRPCHandler<Id, TSpec>>>,
    fork_context: Arc<ForkContext>,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
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
    dial_queue: SmallVec<[(Id, MockOutboundRequest<TSpec>); 4]>,

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

#[derive(Debug, Clone)]
struct MockOutboundRequestContainer<TSpec: EthSpec> {
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

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<TSpec: EthSpec> MockOutboundRequest<TSpec> {
    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            MockOutboundRequest::Status(_) => vec![ProtocolId::new(
                Protocol::Status,
                Version::V1,
                Encoding::SSZSnappy,
            )],
            MockOutboundRequest::Goodbye(_) => vec![ProtocolId::new(
                Protocol::Goodbye,
                Version::V1,
                Encoding::SSZSnappy,
            )],
            MockOutboundRequest::Ping(_) => vec![ProtocolId::new(
                Protocol::Ping,
                Version::V1,
                Encoding::SSZSnappy,
            )],
            MockOutboundRequest::MetaData(_) => vec![
                ProtocolId::new(Protocol::MetaData, Version::V2, Encoding::SSZSnappy),
                ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZSnappy),
            ],
            MockOutboundRequest::LightClientBootstrap(_) => vec![ProtocolId::new(
                Protocol::LightClientBootstrap,
                Version::V1,
                Encoding::SSZSnappy,
            )],
        }
    }
    /* These functions are used in the handler for stream management */

    /// Number of responses expected for this request.
    pub fn expected_responses(&self) -> u64 {
        match self {
            MockOutboundRequest::Status(_) => 1,
            MockOutboundRequest::Goodbye(_) => 0,
            MockOutboundRequest::Ping(_) => 1,
            MockOutboundRequest::MetaData(_) => 1,
            MockOutboundRequest::LightClientBootstrap(_) => 1,
        }
    }

    /// Gives the corresponding `Protocol` to this request.
    pub fn protocol(&self) -> Protocol {
        match self {
            MockOutboundRequest::Status(_) => Protocol::Status,
            MockOutboundRequest::Goodbye(_) => Protocol::Goodbye,
            MockOutboundRequest::Ping(_) => Protocol::Ping,
            MockOutboundRequest::MetaData(_) => Protocol::MetaData,
            MockOutboundRequest::LightClientBootstrap(_) => Protocol::LightClientBootstrap,
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            MockOutboundRequest::LightClientBootstrap(_) => unreachable!(),
            MockOutboundRequest::Status(_) => unreachable!(),
            MockOutboundRequest::Goodbye(_) => unreachable!(),
            MockOutboundRequest::Ping(_) => unreachable!(),
            MockOutboundRequest::MetaData(_) => unreachable!(),
        }
    }
}

struct ResponseTermination {}

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

pub struct BaseOutboundCodec<TOutboundCodec, TSpec>
where
    TOutboundCodec: OutboundCodec<OutboundRequest<TSpec>>,
    TSpec: EthSpec,
{
    /// Inner codec for handling various encodings.
    inner: TOutboundCodec,
    /// Keeps track of the current response code for a chunk.
    current_response_code: Option<u8>,
    phantom: PhantomData<TSpec>,
}

impl<TOutboundCodec, TSpec> BaseOutboundCodec<TOutboundCodec, TSpec>
where
    TSpec: EthSpec,
    TOutboundCodec: OutboundCodec<OutboundRequest<TSpec>>,
{
    pub fn new(codec: TOutboundCodec) -> Self {
        BaseOutboundCodec {
            inner: codec,
            current_response_code: None,
            phantom: PhantomData,
        }
    }
}

impl<TCodec, TSpec> Encoder<OutboundRequest<TSpec>> for BaseOutboundCodec<TCodec, TSpec>
where
    TSpec: EthSpec,
    TCodec: OutboundCodec<OutboundRequest<TSpec>> + Encoder<OutboundRequest<TSpec>>,
{
    type Error = <TCodec as Encoder<OutboundRequest<TSpec>>>::Error;

    fn encode(
        &mut self,
        item: OutboundRequest<TSpec>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        self.inner.encode(item, dst)
    }
}

// This decodes RPC Responses received from external peers
impl<TCodec, TSpec> Decoder for BaseOutboundCodec<TCodec, TSpec>
where
    TSpec: EthSpec,
    TCodec: OutboundCodec<OutboundRequest<TSpec>, CodecErrorType = ErrorType>
        + Decoder<Item = RPCResponse<TSpec>>,
{
    type Item = RPCCodedResponse<TSpec>;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // if we have only received the response code, wait for more bytes
        if src.len() <= 1 {
            return Ok(None);
        }
        // using the response code determine which kind of payload needs to be decoded.
        let response_code = self.current_response_code.unwrap_or_else(|| {
            let resp_code = src.split_to(1)[0];
            self.current_response_code = Some(resp_code);
            resp_code
        });

        let inner_result = {
            if RPCCodedResponse::<TSpec>::is_response(response_code) {
                // decode an actual response and mutates the buffer if enough bytes have been read
                // returning the result.
                self.inner
                    .decode(src)
                    .map(|r| r.map(RPCCodedResponse::Success))
            } else {
                // decode an error
                self.inner
                    .decode_error(src)
                    .map(|r| r.map(|resp| RPCCodedResponse::from_error(response_code, resp)))
            }
        };
        // if the inner decoder was capable of decoding a chunk, we need to reset the current
        // response code for the next chunk
        if let Ok(Some(_)) = inner_result {
            self.current_response_code = None;
        }
        // return the result
        inner_result
    }
}

/// RPC events sent from Lighthouse.
#[derive(Debug, Clone)]
pub enum MockRPCSend<Id, TSpec: EthSpec> {
    /// A request sent from Lighthouse.
    ///
    /// The `Id` is given by the application making the request. These
    /// go over *outbound* connections.
    Request(Id, MockOutboundRequest<TSpec>),
    /// A response sent from Lighthouse.
    ///
    /// The `SubstreamId` must correspond to the RPC-given ID of the original request received from the
    /// peer. The second parameter is a single chunk of a response. These go over *inbound*
    /// connections.
    Response(SubstreamId, RPCCodedResponse<TSpec>),
    /// Lighthouse has requested to terminate the connection with a goodbye message.
    Shutdown(Id, GoodbyeReason),
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
                    proto: req.protocol(),
                    id,
                }));
            }

            // Queue our goodbye message.
            if let Some((id, reason)) = goodbye_reason {
                self.dial_queue.push((id, MockOutboundRequest::Goodbye(reason)));
            }

            self.state = HandlerState::ShuttingDown(Box::pin(sleep_until(
                TInstant::now() + Duration::from_secs(SHUTDOWN_TIMEOUT_SECS as u64),
            )));
        }
    }

    /// Opens an outbound substream with a request.
    fn send_request(&mut self, id: Id, req: MockOutboundRequest<TSpec>) {
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

/// Contains the information the handler keeps on established outbound substreams.
pub struct MockOutboundInfo<Id, TSpec: EthSpec> {
    /// State of the substream.
    state: MockOutboundSubstreamState<TSpec>,
    /// Key to keep track of the substream's timeout via `self.outbound_substreams_delay`.
    delay_key: delay_queue::Key,
    /// Info over the protocol this substream is handling.
    proto: Protocol,
    /// Number of chunks to be seen from the peer's response.
    remaining_chunks: Option<u64>,
    /// `Id` as given by the application that sent the request.
    req_id: Id,
}

/// State of an outbound substream. Either waiting for a response, or in the process of sending.
pub enum MockOutboundSubstreamState<TSpec: EthSpec> {
    /// A request has been sent, and we are awaiting a response. This future is driven in the
    /// handler because GOODBYE requests can be handled and responses dropped instantly.
    RequestPendingResponse {
        /// The framed negotiated substream.
        substream: Box<OutboundFramed<NegotiatedSubstream, TSpec>>,
        /// Keeps track of the actual request sent.
        request: MockOutboundRequest<TSpec>,
    },
    /// Closing an outbound substream>
    Closing(Box<OutboundFramed<NegotiatedSubstream, TSpec>>),
    /// Temporary state during processing
    Poisoned,
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
    type OutboundOpenInfo = (Id, MockOutboundRequest<TSpec>); // Keep track of the id and the request
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
            let awaiting_stream = MockOutboundSubstreamState::RequestPendingResponse {
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
                    MockOutboundInfo {
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
                        protocol: req.protocol(),
                        request_start_time: Instant::now(),
                        remaining_chunks: expected_responses,
                    },
                );
            } else {
                self.events_out.push(Err(HandlerErr::Inbound {
                    id: self.current_inbound_substream_id,
                    proto: req.protocol(),
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
                                Protocol::BlocksByRange => Some(ResponseTermination::BlocksByRange),
                                Protocol::BlocksByRoot => Some(ResponseTermination::BlocksByRoot),
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
