#![cfg(test)]
use std::marker::PhantomData;
use std::sync::{Weak, Arc};
use fnv::FnvHashMap;
use futures::future::BoxFuture;
use futures::{AsyncWrite, AsyncRead};
use libp2p::OutboundUpgrade;
use libp2p::core::UpgradeInfo;
use lighthouse_network::rpc::methods::Ping;
use lighthouse_network::rpc::{ReqId, RPCMessage, SubstreamId, ProtocolId, Protocol, Version, Encoding, HandlerEvent, InboundInfo, HandlerState, OutboundInfo, StatusMessage, GoodbyeReason, LightClientBootstrapRequest, OutboundFramed, RPCError, OutboundCodec, BaseOutboundCodec, SSZSnappyOutboundCodec};
use smallvec::SmallVec;
use tokio::runtime::Runtime;
use tokio_util::codec::Framed;
use tokio_util::time::DelayQueue;
use types::{EthSpec, ForkContext};
use types::{
    ForkName, 
};
use slog::{o, debug, error};
use std::time::Duration;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction};
use libp2p::swarm::handler::{
    SubstreamProtocol,
};


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

#[derive(Debug, Clone)]
struct MockRPCProtocol<TSpec: EthSpec> {
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
    pub enable_light_client_server: bool,
    pub phantom: PhantomData<TSpec>,
}

impl<TSpec: EthSpec> UpgradeInfo for MockRPCProtocol<TSpec> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    /// The list of supported RPC protocols for Lighthouse.
    fn protocol_info(&self) -> Self::InfoIter {
        vec![
            ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::Goodbye, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::Ping, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::MetaData, Version::V2, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::MetaData, Version::V1, Encoding::SSZSnappy),
            ProtocolId::new(Protocol::LightClientBootstrap, Version::V1, Encoding::SSZSnappy),
        ]
    }
}

// We have to reimplement the ConnectionHandler trait for a struct that allows outbound
// light client requests.
pub struct MockRPCHandler<Id, TSpec>
where
    TSpec: EthSpec,
{
    /// The upgrade for inbound substreams.
    listen_protocol: SubstreamProtocol<MockRPCProtocol<TSpec>, ()>,

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
    pub req: MockOutboundRequest<TSpec>,
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum MockOutboundRequest<TSpec: EthSpec> {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    LightClientBootstrap(LightClientBootstrapRequest),
    Ping(Ping),
    MetaData(PhantomData<TSpec>),
}

impl<TSpec: EthSpec> UpgradeInfo for MockOutboundRequestContainer<TSpec> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        self.req.supported_protocols()
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
