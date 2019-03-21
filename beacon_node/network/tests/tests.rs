use beacon_chain::test_utils::TestingBeaconChainBuilder;
use crossbeam_channel::{unbounded, Receiver, Sender};
use libp2p::rpc::{HelloMessage, RPCMethod, RPCRequest, RPCResponse};
use libp2p::{PeerId, RPCEvent};
use network::beacon_chain::BeaconChain as NetworkBeaconChain;
use network::message_handler::{HandlerMessage, MessageHandler};
use network::service::{NetworkMessage, OutgoingMessage};
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;
use std::sync::Arc;
use test_harness::BeaconChainHarness;
use tokio::runtime::TaskExecutor;
use types::{test_utils::TestingBeaconStateBuilder, *};

pub struct SyncNode {
    pub id: usize,
    sender: Sender<HandlerMessage>,
    receiver: Receiver<NetworkMessage>,
}

impl SyncNode {
    pub fn new(
        id: usize,
        executor: &TaskExecutor,
        chain: Arc<NetworkBeaconChain>,
        logger: slog::Logger,
    ) -> Self {
        let (network_sender, network_receiver) = unbounded();
        let message_handler_sender =
            MessageHandler::spawn(chain, network_sender, executor, logger).unwrap();

        Self {
            id,
            sender: message_handler_sender,
            receiver: network_receiver,
        }
    }

    fn send(&self, message: HandlerMessage) {
        self.sender.send(message).unwrap();
    }

    fn recv(&self) -> NetworkMessage {
        self.receiver.recv().unwrap()
    }

    fn recv_rpc_response(&self) -> RPCResponse {
        let network_message = self.recv();
        match network_message {
            NetworkMessage::Send(
                _peer_id,
                OutgoingMessage::RPC(RPCEvent::Response {
                    id: _,
                    method_id: _,
                    result,
                }),
            ) => result,
            _ => panic!("get_rpc_response failed! got {:?}", network_message),
        }
    }

    fn recv_rpc_request(&self) -> RPCRequest {
        let network_message = self.recv();
        match network_message {
            NetworkMessage::Send(
                _peer_id,
                OutgoingMessage::RPC(RPCEvent::Request {
                    id: _,
                    method_id: _,
                    body,
                }),
            ) => body,
            _ => panic!("get_rpc_request failed! got {:?}", network_message),
        }
    }
}

fn get_logger() -> slog::Logger {
    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Debug);
    builder.destination(Destination::Stderr);
    builder.build().unwrap()
}

pub struct SyncMaster {
    harness: BeaconChainHarness,
    peer_id: PeerId,
    response_ids: Vec<u64>,
}

impl SyncMaster {
    fn from_beacon_state_builder(
        state_builder: TestingBeaconStateBuilder,
        node_count: usize,
        spec: &ChainSpec,
    ) -> Self {
        let harness = BeaconChainHarness::from_beacon_state_builder(state_builder, spec.clone());
        let peer_id = PeerId::random();
        let response_ids = vec![0; node_count];

        Self {
            harness,
            peer_id,
            response_ids,
        }
    }

    pub fn response_id(&mut self, node: &SyncNode) -> u64 {
        let id = self.response_ids[node.id];
        self.response_ids[node.id] += 1;
        id
    }

    pub fn do_hello_with(&mut self, node: &SyncNode) {
        let message = HandlerMessage::PeerDialed(self.peer_id.clone());
        node.send(message);

        let request = node.recv_rpc_request();

        match request {
            RPCRequest::Hello(_hello) => {
                let hello = self.harness.beacon_chain.hello_message();
                let response = self.rpc_response(node, RPCResponse::Hello(hello));
                node.send(response);
            }
            _ => panic!("Got message other than hello from node."),
        }
    }

    fn rpc_response(&mut self, node: &SyncNode, rpc_response: RPCResponse) -> HandlerMessage {
        HandlerMessage::RPC(
            self.peer_id.clone(),
            RPCEvent::Response {
                id: self.response_id(node),
                method_id: RPCMethod::Hello.into(),
                result: rpc_response,
            },
        )
    }
}

fn test_setup(
    state_builder: TestingBeaconStateBuilder,
    node_count: usize,
    spec: &ChainSpec,
    logger: slog::Logger,
) -> (tokio::runtime::Runtime, SyncMaster, Vec<SyncNode>) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut nodes = Vec::with_capacity(node_count);
    for id in 0..node_count {
        let local_chain = TestingBeaconChainBuilder::from(state_builder.clone()).build(&spec);
        let node = SyncNode::new(
            id,
            &runtime.executor(),
            Arc::new(local_chain),
            logger.clone(),
        );

        nodes.push(node);
    }

    let master = SyncMaster::from_beacon_state_builder(state_builder, node_count, &spec);

    (runtime, master, nodes)
}

#[test]
fn first_test() {
    let logger = get_logger();
    let spec = ChainSpec::few_validators();
    let validator_count = 8;
    let node_count = 1;

    let state_builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec);

    let (runtime, mut master, nodes) = test_setup(state_builder, node_count, &spec, logger.clone());

    master.do_hello_with(&nodes[0]);

    runtime.shutdown_now();
}
