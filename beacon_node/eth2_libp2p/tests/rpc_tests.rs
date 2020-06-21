#![cfg(test)]
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::{BehaviourEvent, Libp2pEvent, Request, Response};
use slog::{debug, warn, Level};
use ssz_types::VariableList;
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
    let rpc_request = Request::Status(StatusMessage {
        fork_digest: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    // Dummy STATUS RPC message
    let rpc_response = Response::Status(StatusMessage {
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
                        .send_request(peer_id, RequestId::Sync(10), rpc_request.clone());
                }
                Libp2pEvent::Behaviour(BehaviourEvent::ResponseReceived {
                    peer_id: _,
                    id: RequestId::Sync(10),
                    response,
                }) => {
                    // Should receive the RPC response
                    debug!(log, "Sender Received");
                    assert_eq!(response, rpc_response.clone());
                    debug!(log, "Sender Completed");
                    return;
                }
                _ => {}
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                }) => {
                    if request == rpc_request {
                        // send the response
                        debug!(log, "Receiver Received");
                        receiver
                            .swarm
                            .send_successful_response(peer_id, id, rpc_response.clone());
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_secs(30)) => {
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
    let rpc_request = Request::BlocksByRange(BlocksByRangeRequest {
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
    let rpc_response = Response::BlocksByRange(Some(Box::new(empty_signed)));

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
                        .send_request(peer_id, RequestId::Sync(10), rpc_request.clone());
                }
                Libp2pEvent::Behaviour(BehaviourEvent::ResponseReceived {
                    peer_id: _,
                    id: RequestId::Sync(10),
                    response,
                }) => {
                    warn!(log, "Sender received a response");
                    match response {
                        Response::BlocksByRange(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                            warn!(log, "Chunk received");
                        }
                        Response::BlocksByRange(None) => {
                            // should be exactly 10 messages before terminating
                            assert_eq!(messages_received, messages_to_send);
                            // end the test
                            return;
                        }
                        _ => panic!("Invalid RPC received"),
                    }
                }
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                }) => {
                    if request == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
                        for _ in 1..=messages_to_send {
                            receiver.swarm.send_successful_response(
                                peer_id.clone(),
                                id,
                                rpc_response.clone(),
                            );
                        }
                        // send the stream termination
                        receiver.swarm.send_successful_response(
                            peer_id,
                            id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
// Tests that a streamed BlocksByRange RPC Message terminates when all expected chunks were received
async fn test_blocks_by_range_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 10;
    let extra_messages_to_send = 10;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log).await;

    // BlocksByRange Request
    let rpc_request = Request::BlocksByRange(BlocksByRangeRequest {
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
    let rpc_response = Response::BlocksByRange(Some(Box::new(empty_signed)));

    // keep count of the number of messages received
    let mut messages_received: u64 = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                Libp2pEvent::PeerConnected { peer_id, .. } => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .swarm
                        .send_request(peer_id, RequestId::Sync(10), rpc_request.clone());
                }
                Libp2pEvent::Behaviour(BehaviourEvent::ResponseReceived {
                    peer_id: _,
                    id: RequestId::Sync(10),
                    response,
                }) =>
                // Should receive the RPC response
                {
                    debug!(log, "Sender received a response");
                    match response {
                        Response::BlocksByRange(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                        }
                        Response::BlocksByRange(None) => {
                            // should be exactly 10 messages, as requested
                            assert_eq!(messages_received, messages_to_send);
                        }
                        _ => panic!("Invalid RPC received"),
                    }
                }

                _ => {} // Ignore other behaviour events
            }
        }
    };

    // determine messages to send (PeerId, RequestId). If some, indicates we still need to send
    // messages
    let mut message_info = None;
    // the number of messages we've sent
    let mut messages_sent = 0;
    let receiver_future = async {
        loop {
            // this future either drives the sending/receiving or times out allowing messages to be
            // sent in the timeout
            match futures::future::select(
                Box::pin(receiver.next_event()),
                tokio::time::delay_for(Duration::from_secs(1)),
            )
            .await
            {
                futures::future::Either::Left((
                    Libp2pEvent::Behaviour(BehaviourEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    }),
                    _,
                )) => {
                    if request == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
                        message_info = Some((peer_id, id));
                    }
                }
                futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                _ => continue,
            }

            // if we need to send messages send them here. This will happen after a delay
            if message_info.is_some() {
                messages_sent += 1;
                let (peer_id, stream_id) = message_info.as_ref().unwrap();
                receiver.swarm.send_successful_response(
                    peer_id.clone(),
                    stream_id.clone(),
                    rpc_response.clone(),
                );
                debug!(log, "Sending message {}", messages_sent);
                if messages_sent == messages_to_send + extra_messages_to_send {
                    // stop sending messages
                    return;
                }
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_secs(30)) => {
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
    let rpc_request = Request::BlocksByRange(BlocksByRangeRequest {
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
    let rpc_response = Response::BlocksByRange(Some(Box::new(empty_signed)));

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
                        .send_request(peer_id, RequestId::Sync(10), rpc_request.clone());
                }
                Libp2pEvent::Behaviour(BehaviourEvent::ResponseReceived {
                    peer_id: _,
                    id: RequestId::Sync(10),
                    response,
                }) => match response {
                    Response::BlocksByRange(Some(_)) => {
                        assert_eq!(response, rpc_response.clone());
                        messages_received += 1;
                        warn!(log, "Chunk received");
                    }
                    Response::BlocksByRange(None) => {
                        // should be exactly 10 messages before terminating
                        assert_eq!(messages_received, messages_to_send);
                        // end the test
                        return;
                    }
                    _ => panic!("Invalid RPC received"),
                },
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                }) => {
                    if request == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");

                        for _ in 1..=messages_to_send {
                            receiver.swarm.send_successful_response(
                                peer_id.clone(),
                                id,
                                rpc_response.clone(),
                            );
                        }
                        // send the stream termination
                        receiver.swarm.send_successful_response(
                            peer_id,
                            id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };
    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_secs(20)) => {
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
    let rpc_request = Request::BlocksByRoot(BlocksByRootRequest {
        block_roots: VariableList::from(vec![
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
        ]),
    });

    // BlocksByRoot Response
    let full_block = BeaconBlock::full(&spec);
    let signed_full_block = SignedBeaconBlock {
        message: full_block,
        signature: Signature::empty_signature(),
    };
    let rpc_response = Response::BlocksByRoot(Some(Box::new(signed_full_block)));

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
                        .send_request(peer_id, RequestId::Sync(10), rpc_request.clone());
                }
                Libp2pEvent::Behaviour(BehaviourEvent::ResponseReceived {
                    peer_id: _,
                    id: RequestId::Sync(10),
                    response,
                }) => match response {
                    Response::BlocksByRoot(Some(_)) => {
                        assert_eq!(response, rpc_response.clone());
                        messages_received += 1;
                        debug!(log, "Chunk received");
                    }
                    Response::BlocksByRoot(None) => {
                        // should be exactly messages_to_send
                        assert_eq!(messages_received, messages_to_send);
                        // end the test
                        return;
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
                Libp2pEvent::Behaviour(BehaviourEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                }) => {
                    if request == rpc_request {
                        // send the response
                        debug!(log, "Receiver got request");

                        for _ in 1..=messages_to_send {
                            receiver.swarm.send_successful_response(
                                peer_id.clone(),
                                id,
                                rpc_response.clone(),
                            );
                            debug!(log, "Sending message");
                        }
                        // send the stream termination
                        receiver.swarm.send_successful_response(
                            peer_id,
                            id,
                            Response::BlocksByRange(None),
                        );
                        debug!(log, "Send stream term");
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };
    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
// Tests a streamed, chunked BlocksByRoot RPC Message terminates when all expected reponses have been received
async fn test_blocks_by_root_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send: u64 = 10;
    let extra_messages_to_send: u64 = 10;

    let log = common::build_log(log_level, enable_logging);
    let spec = E::default_spec();

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log).await;

    // BlocksByRoot Request
    let rpc_request = Request::BlocksByRoot(BlocksByRootRequest {
        block_roots: VariableList::from(vec![
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
            Hash256::from_low_u64_be(0),
        ]),
    });

    // BlocksByRoot Response
    let full_block = BeaconBlock::full(&spec);
    let signed_full_block = SignedBeaconBlock {
        message: full_block,
        signature: Signature::empty_signature(),
    };
    let rpc_response = Response::BlocksByRoot(Some(Box::new(signed_full_block)));

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
                        .send_request(peer_id, RequestId::Sync(10), rpc_request.clone());
                }
                Libp2pEvent::Behaviour(BehaviourEvent::ResponseReceived {
                    peer_id: _,
                    id: RequestId::Sync(10),
                    response,
                }) => {
                    debug!(log, "Sender received a response");
                    match response {
                        Response::BlocksByRoot(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                            debug!(log, "Chunk received");
                        }
                        Response::BlocksByRoot(None) => {
                            // should be exactly messages_to_send
                            assert_eq!(messages_received, messages_to_send);
                            // end the test
                            return;
                        }
                        _ => {} // Ignore other RPC messages
                    }
                }
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // determine messages to send (PeerId, RequestId). If some, indicates we still need to send
    // messages
    let mut message_info = None;
    // the number of messages we've sent
    let mut messages_sent = 0;
    let receiver_future = async {
        loop {
            // this future either drives the sending/receiving or times out allowing messages to be
            // sent in the timeout
            match futures::future::select(
                Box::pin(receiver.next_event()),
                tokio::time::delay_for(Duration::from_millis(1000)),
            )
            .await
            {
                futures::future::Either::Left((
                    Libp2pEvent::Behaviour(BehaviourEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    }),
                    _,
                )) => {
                    if request == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
                        message_info = Some((peer_id, id));
                    }
                }
                futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                _ => continue,
            }

            // if we need to send messages send them here. This will happen after a delay
            if message_info.is_some() {
                messages_sent += 1;
                let (peer_id, stream_id) = message_info.as_ref().unwrap();
                receiver.swarm.send_successful_response(
                    peer_id.clone(),
                    stream_id.clone(),
                    rpc_response.clone(),
                );
                debug!(log, "Sending message {}", messages_sent);
                if messages_sent == messages_to_send + extra_messages_to_send {
                    // stop sending messages
                    return;
                }
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_secs(30)) => {
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
    let rpc_request = Request::Goodbye(GoodbyeReason::ClientShutdown);

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                Libp2pEvent::PeerConnected { peer_id, .. } => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .swarm
                        .send_request(peer_id, RequestId::Sync(10), rpc_request.clone());
                }
                _ => {} // Ignore other RPC messages
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                Libp2pEvent::Behaviour(BehaviourEvent::RequestReceived {
                    peer_id: _,
                    id: _,
                    request,
                }) => {
                    // Should receive sent RPC request
                    assert_eq!(rpc_request.clone(), request); // receives the goodbye. Nothing left to do
                    return;
                }
                _ => {} // Ignore other events
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}
