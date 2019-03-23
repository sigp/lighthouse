use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCMethod, RPCRequest, RPCResponse};
use eth2_libp2p::{PeerId, RPCEvent};
use network::beacon_chain::BeaconChain as NetworkBeaconChain;
use network::message_handler::{HandlerMessage, MessageHandler};
use network::service::{NetworkMessage, OutgoingMessage};
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;
use std::time::Duration;
use test_harness::BeaconChainHarness;
use tokio::runtime::TaskExecutor;
use types::{test_utils::TestingBeaconStateBuilder, *};

pub struct SyncNode {
    pub id: usize,
    sender: Sender<HandlerMessage>,
    receiver: Receiver<NetworkMessage>,
    harness: BeaconChainHarness,
}

impl SyncNode {
    fn from_beacon_state_builder(
        id: usize,
        executor: &TaskExecutor,
        state_builder: TestingBeaconStateBuilder,
        spec: &ChainSpec,
        logger: slog::Logger,
    ) -> Self {
        let harness = BeaconChainHarness::from_beacon_state_builder(state_builder, spec.clone());

        let (network_sender, network_receiver) = unbounded();
        let message_handler_sender = MessageHandler::spawn(
            harness.beacon_chain.clone(),
            network_sender,
            executor,
            logger,
        )
        .unwrap();

        Self {
            id,
            sender: message_handler_sender,
            receiver: network_receiver,
            harness,
        }
    }

    fn increment_beacon_chain_slot(&mut self) {
        self.harness.increment_beacon_chain_slot();
    }

    fn send(&self, message: HandlerMessage) {
        self.sender.send(message).unwrap();
    }

    fn recv(&self) -> Result<NetworkMessage, RecvTimeoutError> {
        self.receiver.recv_timeout(Duration::from_millis(500))
    }

    fn hello_message(&self) -> HelloMessage {
        self.harness.beacon_chain.hello_message()
    }

    pub fn get_block_root_request(&self) -> BeaconBlockRootsRequest {
        let request = self.recv_rpc_request().expect("No block root request");

        match request {
            RPCRequest::BeaconBlockRoots(request) => request,
            _ => panic!("Did not get block root request"),
        }
    }

    pub fn get_block_headers_request(&self) -> BeaconBlockHeadersRequest {
        let request = self.recv_rpc_request().expect("No block headers request");

        match request {
            RPCRequest::BeaconBlockHeaders(request) => request,
            _ => panic!("Did not get block headers request"),
        }
    }

    pub fn get_block_bodies_request(&self) -> BeaconBlockBodiesRequest {
        let request = self.recv_rpc_request().expect("No block bodies request");

        match request {
            RPCRequest::BeaconBlockBodies(request) => request,
            _ => panic!("Did not get block bodies request"),
        }
    }

    fn _recv_rpc_response(&self) -> Result<RPCResponse, RecvTimeoutError> {
        let network_message = self.recv()?;
        Ok(match network_message {
            NetworkMessage::Send(
                _peer_id,
                OutgoingMessage::RPC(RPCEvent::Response {
                    id: _,
                    method_id: _,
                    result,
                }),
            ) => result,
            _ => panic!("get_rpc_response failed! got {:?}", network_message),
        })
    }

    fn recv_rpc_request(&self) -> Result<RPCRequest, RecvTimeoutError> {
        let network_message = self.recv()?;
        Ok(match network_message {
            NetworkMessage::Send(
                _peer_id,
                OutgoingMessage::RPC(RPCEvent::Request {
                    id: _,
                    method_id: _,
                    body,
                }),
            ) => body,
            _ => panic!("get_rpc_request failed! got {:?}", network_message),
        })
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

        let request = node.recv_rpc_request().expect("No hello response");

        match request {
            RPCRequest::Hello(_hello) => {
                let hello = self.harness.beacon_chain.hello_message();
                let response = self.rpc_response(node, RPCResponse::Hello(hello));
                node.send(response);
            }
            _ => panic!("Got message other than hello from node."),
        }
    }

    pub fn respond_to_block_roots_request(
        &mut self,
        node: &SyncNode,
        request: BeaconBlockRootsRequest,
    ) {
        let roots = self
            .harness
            .beacon_chain
            .get_block_roots(request.start_slot, Slot::from(request.count))
            .expect("Beacon chain did not give block roots")
            .iter()
            .enumerate()
            .map(|(i, root)| BlockRootSlot {
                block_root: *root,
                slot: Slot::from(i) + request.start_slot,
            })
            .collect();

        let response = RPCResponse::BeaconBlockRoots(BeaconBlockRootsResponse { roots });
        self.send_rpc_response(node, response)
    }

    pub fn respond_to_block_headers_request(
        &mut self,
        node: &SyncNode,
        request: BeaconBlockHeadersRequest,
    ) {
        let roots = self
            .harness
            .beacon_chain
            .get_block_roots(request.start_slot, Slot::from(request.max_headers))
            .expect("Beacon chain did not give blocks");

        if roots.is_empty() {
            panic!("Roots was empty when trying to get headers.")
        }

        assert_eq!(
            roots[0], request.start_root,
            "Got the wrong start root when getting headers"
        );

        let headers: Vec<BeaconBlockHeader> = roots
            .iter()
            .map(|root| {
                let block = self
                    .harness
                    .beacon_chain
                    .get_block(root)
                    .expect("Failed to load block")
                    .expect("Block did not exist");
                block.block_header()
            })
            .collect();

        let response = RPCResponse::BeaconBlockHeaders(BeaconBlockHeadersResponse { headers });
        self.send_rpc_response(node, response)
    }

    pub fn respond_to_block_bodies_request(
        &mut self,
        node: &SyncNode,
        request: BeaconBlockBodiesRequest,
    ) {
        let block_bodies: Vec<BeaconBlockBody> = request
            .block_roots
            .iter()
            .map(|root| {
                let block = self
                    .harness
                    .beacon_chain
                    .get_block(root)
                    .expect("Failed to load block")
                    .expect("Block did not exist");
                block.body
            })
            .collect();

        let response = RPCResponse::BeaconBlockBodies(BeaconBlockBodiesResponse { block_bodies });
        self.send_rpc_response(node, response)
    }

    fn send_rpc_response(&mut self, node: &SyncNode, rpc_response: RPCResponse) {
        node.send(self.rpc_response(node, rpc_response));
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
        let node = SyncNode::from_beacon_state_builder(
            id,
            &runtime.executor(),
            state_builder.clone(),
            &spec,
            logger.clone(),
        );

        nodes.push(node);
    }

    let master = SyncMaster::from_beacon_state_builder(state_builder, node_count, &spec);

    (runtime, master, nodes)
}

pub fn build_blocks(blocks: usize, master: &mut SyncMaster, nodes: &mut Vec<SyncNode>) {
    for _ in 0..blocks {
        master.harness.advance_chain_with_block();
        for i in 0..nodes.len() {
            nodes[i].increment_beacon_chain_slot();
        }
    }
    master.harness.run_fork_choice();

    for i in 0..nodes.len() {
        nodes[i].harness.run_fork_choice();
    }
}

#[test]
fn first_test() {
    let logger = get_logger();
    let spec = ChainSpec::few_validators();
    let validator_count = 8;
    let node_count = 1;

    let state_builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec);

    let (runtime, mut master, mut nodes) =
        test_setup(state_builder, node_count, &spec, logger.clone());

    let original_node_slot = nodes[0].hello_message().best_slot;

    build_blocks(2, &mut master, &mut nodes);

    master.do_hello_with(&nodes[0]);

    let roots_request = nodes[0].get_block_root_request();
    assert_eq!(roots_request.start_slot, original_node_slot + 1);
    assert_eq!(roots_request.count, 2);

    master.respond_to_block_roots_request(&nodes[0], roots_request);

    let headers_request = nodes[0].get_block_headers_request();
    assert_eq!(headers_request.start_slot, original_node_slot + 1);
    assert_eq!(headers_request.max_headers, 2);
    assert_eq!(headers_request.skip_slots, 0);

    master.respond_to_block_headers_request(&nodes[0], headers_request);

    let bodies_request = nodes[0].get_block_bodies_request();
    assert_eq!(bodies_request.block_roots.len(), 2);

    master.respond_to_block_bodies_request(&nodes[0], bodies_request);

    std::thread::sleep(Duration::from_millis(10000));
    runtime.shutdown_now();
}
