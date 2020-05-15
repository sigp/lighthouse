#![cfg(test)]
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::*;
use eth2_libp2p::{BehaviourEvent, Libp2pEvent, RPCEvent};
use slog::{debug, warn, Level};
use std::time::Duration;
use tokio::time::delay_for;
use types::{
    BeaconBlock, Epoch, EthSpec, Hash256, MinimalEthSpec, Signature, SignedBeaconBlock, Slot,
};

mod common;

type E = MinimalEthSpec;

#[tokio::test]
// Tests the STATUS RPC message
async fn test_status_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log).await;

    // Dummy STATUS RPC message
    let rpc_request = RPCRequest::Status(StatusMessage {
        fork_digest: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    // Dummy STATUS RPC message
    let rpc_response = RPCResponse::Status(StatusMessage {
        fork_digest: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                Libp2pEvent::PeerConnected { peer_id, .. } => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(10, rpc_request.clone()));
                }
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(_, event)) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response @ RPCCodedResponse::Success(_)) => {
                        if id == 10 {
                            debug!(log, "Sender Received");
                            let response = {
                                match response {
                                    RPCCodedResponse::Success(r) => r,
                                    _ => unreachable!(),
                                }
                            };
                            assert_eq!(response, rpc_response.clone());
                            debug!(log, "Sender Completed");
                            return;
                        }
                    }
                    _ => {} // Ignore other RPC messages
                },
                _ => {}
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(peer_id, event)) => {
                    match event {
                        // Should receive sent RPC request
                        RPCEvent::Request(id, request) => {
                            if request == rpc_request {
                                // send the response
                                debug!(log, "Receiver Received");
                                receiver.swarm.send_rpc(
                                    peer_id,
                                    RPCEvent::Response(
                                        id,
                                        RPCCodedResponse::Success(rpc_response.clone()),
                                    ),
                                );
                            }
                        }
                        _ => {} // Ignore other RPC requests
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_millis(800)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
// Tests a streamed BlocksByRange RPC Message
async fn test_blocks_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let messages_to_send = 10;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log).await;

    // BlocksByRange Request
    let rpc_request = RPCRequest::BlocksByRange(BlocksByRangeRequest {
        start_slot: 0,
        count: messages_to_send,
        step: 0,
    });

    // BlocksByRange Response
    let spec = E::default_spec();
    let empty_block = BeaconBlock::empty(&spec);
    let empty_signed = SignedBeaconBlock {
        message: empty_block,
        signature: Signature::empty_signature(),
    };
    let rpc_response = RPCResponse::BlocksByRange(Box::new(empty_signed));

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                Libp2pEvent::PeerConnected { peer_id, .. } => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(10, rpc_request.clone()));
                }
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(_, event)) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response) => {
                        if id == 10 {
                            warn!(log, "Sender received a response");
                            match response {
                                RPCCodedResponse::Success(res) => {
                                    assert_eq!(res, rpc_response.clone());
                                    messages_received += 1;
                                    warn!(log, "Chunk received");
                                }
                                RPCCodedResponse::StreamTermination(_) => {
                                    // should be exactly 10 messages before terminating
                                    assert_eq!(messages_received, messages_to_send);
                                    // end the test
                                    return;
                                }
                                _ => panic!("Invalid RPC received"),
                            }
                        }
                    }
                    _ => {} // Ignore other RPC messages
                },
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(peer_id, event)) => {
                    match event {
                        // Should receive sent RPC request
                        RPCEvent::Request(id, request) => {
                            if request == rpc_request {
                                // send the response
                                warn!(log, "Receiver got request");

                                for _ in 1..=messages_to_send {
                                    receiver.swarm.send_rpc(
                                        peer_id.clone(),
                                        RPCEvent::Response(
                                            id,
                                            RPCCodedResponse::Success(rpc_response.clone()),
                                        ),
                                    );
                                }
                                // send the stream termination
                                receiver.swarm.send_rpc(
                                    peer_id,
                                    RPCEvent::Response(
                                        id,
                                        RPCCodedResponse::StreamTermination(
                                            ResponseTermination::BlocksByRange,
                                        ),
                                    ),
                                );
                            }
                        }
                        _ => {} // Ignore other events
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_millis(800)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
// Tests an empty response to a BlocksByRange RPC Message
async fn test_blocks_by_range_single_empty_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log).await;

    // BlocksByRange Request
    let rpc_request = RPCRequest::BlocksByRange(BlocksByRangeRequest {
        start_slot: 0,
        count: 10,
        step: 0,
    });

    // BlocksByRange Response
    let spec = E::default_spec();
    let empty_block = BeaconBlock::empty(&spec);
    let empty_signed = SignedBeaconBlock {
        message: empty_block,
        signature: Signature::empty_signature(),
    };
    let rpc_response = RPCResponse::BlocksByRange(Box::new(empty_signed));

    let messages_to_send = 1;

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                Libp2pEvent::PeerConnected { peer_id, .. } => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(10, rpc_request.clone()));
                }
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(_, event)) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response) => {
                        if id == 10 {
                            warn!(log, "Sender received a response");
                            match response {
                                RPCCodedResponse::Success(res) => {
                                    assert_eq!(res, rpc_response.clone());
                                    messages_received += 1;
                                    warn!(log, "Chunk received");
                                }
                                RPCCodedResponse::StreamTermination(_) => {
                                    // should be exactly 10 messages before terminating
                                    assert_eq!(messages_received, messages_to_send);
                                    // end the test
                                    return;
                                }
                                _ => panic!("Invalid RPC received"),
                            }
                        }
                    }
                    _ => {} // Ignore other RPC messages
                },
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(peer_id, event)) => {
                    match event {
                        // Should receive sent RPC request
                        RPCEvent::Request(id, request) => {
                            if request == rpc_request {
                                // send the response
                                warn!(log, "Receiver got request");

                                for _ in 1..=messages_to_send {
                                    receiver.swarm.send_rpc(
                                        peer_id.clone(),
                                        RPCEvent::Response(
                                            id,
                                            RPCCodedResponse::Success(rpc_response.clone()),
                                        ),
                                    );
                                }
                                // send the stream termination
                                receiver.swarm.send_rpc(
                                    peer_id,
                                    RPCEvent::Response(
                                        id,
                                        RPCCodedResponse::StreamTermination(
                                            ResponseTermination::BlocksByRange,
                                        ),
                                    ),
                                );
                            }
                        }
                        _ => {} // Ignore other events
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };
    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_millis(800)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
// Tests a streamed, chunked BlocksByRoot RPC Message
// The size of the reponse is a full `BeaconBlock`
// which is greater than the Snappy frame size. Hence, this test
// serves to test the snappy framing format as well.
async fn test_blocks_by_root_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 3;

    let log = common::build_log(log_level, enable_logging);
    let spec = E::default_spec();

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log).await;

    // BlocksByRoot Request
    let rpc_request = RPCRequest::BlocksByRoot(BlocksByRootRequest {
        block_roots: vec![Hash256::from_low_u64_be(0), Hash256::from_low_u64_be(0)],
    });

    // BlocksByRoot Response
    let full_block = BeaconBlock::full(&spec);
    let signed_full_block = SignedBeaconBlock {
        message: full_block,
        signature: Signature::empty_signature(),
    };
    let rpc_response = RPCResponse::BlocksByRoot(Box::new(signed_full_block));

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                Libp2pEvent::PeerConnected { peer_id, .. } => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(10, rpc_request.clone()));
                }
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(_, event)) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response) => {
                        if id == 10 {
                            debug!(log, "Sender received a response");
                            match response {
                                RPCCodedResponse::Success(res) => {
                                    assert_eq!(res, rpc_response.clone());
                                    messages_received += 1;
                                    debug!(log, "Chunk received");
                                }
                                RPCCodedResponse::StreamTermination(_) => {
                                    // should be exactly messages_to_send
                                    assert_eq!(messages_received, messages_to_send);
                                    // end the test
                                    return;
                                }
                                _ => {} // Ignore other RPC messages
                            }
                        }
                    }
                    _ => {} // Ignore other RPC messages
                },
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(peer_id, event)) => {
                    match event {
                        // Should receive sent RPC request
                        RPCEvent::Request(id, request) => {
                            if request == rpc_request {
                                // send the response
                                debug!(log, "Receiver got request");

                                for _ in 1..=messages_to_send {
                                    receiver.swarm.send_rpc(
                                        peer_id.clone(),
                                        RPCEvent::Response(
                                            id,
                                            RPCCodedResponse::Success(rpc_response.clone()),
                                        ),
                                    );
                                    debug!(log, "Sending message");
                                }
                                // send the stream termination
                                receiver.swarm.send_rpc(
                                    peer_id,
                                    RPCEvent::Response(
                                        id,
                                        RPCCodedResponse::StreamTermination(
                                            ResponseTermination::BlocksByRange,
                                        ),
                                    ),
                                );
                                debug!(log, "Send stream term");
                            }
                        }
                        _ => {} // Ignore other events
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };
    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_millis(1000)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
// Tests a Goodbye RPC message
async fn test_goodbye_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log).await;

    // Goodbye Request
    let rpc_request = RPCRequest::Goodbye(GoodbyeReason::ClientShutdown);

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                Libp2pEvent::PeerConnected { peer_id, .. } => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(10, rpc_request.clone()));
                }
                _ => {} // Ignore other RPC messages
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RPC(_peer_id, event)) => {
                    match event {
                        // Should receive sent RPC request
                        RPCEvent::Request(id, request) => {
                            if request == rpc_request {
                                assert_eq!(id, 0);
                                assert_eq!(rpc_request.clone(), request); // receives the goodbye. Nothing left to do
                                return;
                            }
                        }
                        _ => {} // Ignore other events
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_millis(1000)) => {
            panic!("Future timed out");
        }
    }
}
