#![cfg(test)]
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::*;
use eth2_libp2p::{BehaviourEvent, Libp2pEvent, RPCEvent};
use futures::prelude::*;
use slog::{debug, error, warn, Level};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::prelude::*;
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
    let enable_logging = true;

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

    let rpc_req = rpc_request.clone();
    let rpc_resp = rpc_response.clone();
    let log1 = log.clone();

    // build the sender future
    let sender_future = async move {
        loop {
            while let Some(sender_event) = sender.next().await {
                match sender_event {
                    Libp2pEvent::Behaviour(BehaviourEvent::PeerDialed(peer_id)) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .swarm
                            .send_rpc(peer_id, RPCEvent::Request(1, rpc_request.clone()));
                    }
                    Libp2pEvent::ConnectionEstablished { .. } => {
                        debug!(log, "Connection established");
                    }
                    Libp2pEvent::Behaviour(BehaviourEvent::RPC(_, event)) => match event {
                        // Should receive the RPC response
                        RPCEvent::Response(id, response @ RPCCodedResponse::Success(_)) => {
                            if id == 1 {
                                debug!(log, "Sender Received");
                                let response = {
                                    match response {
                                        RPCCodedResponse::Success(r) => r,
                                        _ => unreachable!(),
                                    }
                                };
                                assert_eq!(response, rpc_response.clone());

                                debug!(log, "Sender Completed");
                            }
                        }
                        e => panic!("Received invalid RPC message {}", e),
                    },
                    x => debug!(log, "Sender Event:"; "e:"=> format!("{:?}",x)), // ignore other events
                }
            }
        }
    };

    // build the receiver future
    let receiver_future = async move {
        loop {
            while let Some(recv_event) = receiver.next().await {
                match recv_event {
                    Libp2pEvent::Behaviour(BehaviourEvent::RPC(peer_id, event)) => {
                        match event {
                            // Should receive sent RPC request
                            RPCEvent::Request(id, request) => {
                                if request == rpc_req {
                                    // send the response
                                    debug!(log1, "Receiver Received");
                                    receiver.swarm.send_rpc(
                                        peer_id,
                                        RPCEvent::Response(
                                            id,
                                            RPCCodedResponse::Success(rpc_resp.clone()),
                                        ),
                                    );
                                }
                            }
                            e => panic!("Received invalid RPC message {}", e),
                        }
                    }
                    x => debug!(log1, "Receiver Event:"; "e:"=> format!("{:?}",x)), // ignore other events
                }
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = delay_for(Duration::from_millis(2800)) => {
            panic!("Future timed out");
        }
    }
}

/*
#[test]
// Tests a streamed BlocksByRange RPC Message
fn test_blocks_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let messages_to_send = 10;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log);

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

    let sender_request = rpc_request.clone();
    let sender_log = log.clone();
    let sender_response = rpc_response.clone();

    // keep count of the number of messages received
    let messages_received = Arc::new(Mutex::new(0));
    // build the sender future
    let sender_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match sender.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::PeerDialed(peer_id))) => {
                    // Send a BlocksByRange request
                    warn!(sender_log, "Sender sending RPC request");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(1, sender_request.clone()));
                }
                Async::Ready(Some(BehaviourEvent::RPC(_, event))) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response) => {
                        if id == 1 {
                            warn!(sender_log, "Sender received a response");
                            match response {
                                RPCCodedResponse::Success(res) => {
                                    assert_eq!(res, sender_response.clone());
                                    *messages_received.lock().unwrap() += 1;
                                    warn!(sender_log, "Chunk received");
                                }
                                RPCCodedResponse::StreamTermination(
                                    ResponseTermination::BlocksByRange,
                                ) => {
                                    // should be exactly 10 messages before terminating
                                    assert_eq!(
                                        *messages_received.lock().unwrap(),
                                        messages_to_send
                                    );
                                    // end the test
                                    return Ok(Async::Ready(true));
                                }
                                _ => panic!("Invalid RPC received"),
                            }
                        }
                    }
                    _ => panic!("Received invalid RPC message"),
                },
                Async::Ready(Some(_)) => {}
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    // build the receiver future
    let receiver_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match receiver.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::RPC(peer_id, event))) => match event {
                    // Should receive the sent RPC request
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
                    _ => panic!("Received invalid RPC message"),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            }
        }
    });

    // execute the futures and check the result
    let test_result = Arc::new(AtomicBool::new(false));
    let error_result = test_result.clone();
    let thread_result = test_result.clone();
    tokio::run(
        sender_future
            .select(receiver_future)
            .timeout(Duration::from_millis(1000))
            .map_err(move |_| error_result.store(false, Relaxed))
            .map(move |result| {
                thread_result.store(result.0, Relaxed);
            }),
    );
    assert!(test_result.load(Relaxed));
}

#[test]
// Tests an empty response to a BlocksByRange RPC Message
fn test_blocks_by_range_single_empty_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log);

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

    let sender_request = rpc_request.clone();
    let sender_log = log.clone();
    let sender_response = rpc_response.clone();

    // keep count of the number of messages received
    let messages_received = Arc::new(Mutex::new(0));
    // build the sender future
    let sender_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match sender.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::PeerDialed(peer_id))) => {
                    // Send a BlocksByRange request
                    warn!(sender_log, "Sender sending RPC request");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(1, sender_request.clone()));
                }
                Async::Ready(Some(BehaviourEvent::RPC(_, event))) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response) => {
                        if id == 1 {
                            warn!(sender_log, "Sender received a response");
                            match response {
                                RPCCodedResponse::Success(res) => {
                                    assert_eq!(res, sender_response.clone());
                                    *messages_received.lock().unwrap() += 1;
                                    warn!(sender_log, "Chunk received");
                                }
                                RPCCodedResponse::StreamTermination(
                                    ResponseTermination::BlocksByRange,
                                ) => {
                                    // should be exactly 1 messages before terminating
                                    assert_eq!(*messages_received.lock().unwrap(), 1);
                                    // end the test
                                    return Ok(Async::Ready(true));
                                }
                                _ => panic!("Invalid RPC received"),
                            }
                        }
                    }
                    m => panic!("Received invalid RPC message: {}", m),
                },
                Async::Ready(Some(_)) => {}
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    // build the receiver future
    let receiver_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match receiver.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::RPC(peer_id, event))) => match event {
                    // Should receive the sent RPC request
                    RPCEvent::Request(id, request) => {
                        if request == rpc_request {
                            // send the response
                            warn!(log, "Receiver got request");

                            receiver.swarm.send_rpc(
                                peer_id.clone(),
                                RPCEvent::Response(
                                    id,
                                    RPCCodedResponse::Success(rpc_response.clone()),
                                ),
                            );
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
                    _ => panic!("Received invalid RPC message"),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            }
        }
    });

    // execute the futures and check the result
    let test_result = Arc::new(AtomicBool::new(false));
    let error_result = test_result.clone();
    let thread_result = test_result.clone();
    tokio::run(
        sender_future
            .select(receiver_future)
            .timeout(Duration::from_millis(1000))
            .map_err(move |_| error_result.store(false, Relaxed))
            .map(move |result| {
                thread_result.store(result.0, Relaxed);
            }),
    );
    assert!(test_result.load(Relaxed));
}

#[test]
// Tests a streamed, chunked BlocksByRoot RPC Message
// The size of the reponse is a full `BeaconBlock`
// which is greater than the Snappy frame size. Hence, this test
// serves to test the snappy framing format as well.
fn test_blocks_by_root_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let messages_to_send = 3;

    let log = common::build_log(log_level, enable_logging);
    let spec = E::default_spec();

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log);

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

    let sender_request = rpc_request.clone();
    let sender_log = log.clone();
    let sender_response = rpc_response.clone();

    // keep count of the number of messages received
    let messages_received = Arc::new(Mutex::new(0));
    // build the sender future
    let sender_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match sender.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::PeerDialed(peer_id))) => {
                    // Send a BlocksByRoot request
                    warn!(sender_log, "Sender sending RPC request");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(1, sender_request.clone()));
                }
                Async::Ready(Some(BehaviourEvent::RPC(_, event))) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response) => {
                        warn!(sender_log, "Sender received a response");
                        assert_eq!(id, 1);
                        match response {
                            RPCCodedResponse::Success(res) => {
                                assert_eq!(res, sender_response.clone());
                                *messages_received.lock().unwrap() += 1;
                                warn!(sender_log, "Chunk received");
                            }
                            RPCCodedResponse::StreamTermination(
                                ResponseTermination::BlocksByRoot,
                            ) => {
                                // should be exactly 10 messages before terminating
                                assert_eq!(*messages_received.lock().unwrap(), messages_to_send);
                                // end the test
                                return Ok(Async::Ready(true));
                            }
                            m => panic!("Invalid RPC received: {}", m),
                        }
                    }
                    m => panic!("Received invalid RPC message: {}", m),
                },
                Async::Ready(Some(_)) => {}
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    // build the receiver future
    let receiver_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match receiver.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::RPC(peer_id, event))) => match event {
                    // Should receive the sent RPC request
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
                    _ => panic!("Received invalid RPC message"),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            }
        }
    });

    // execute the futures and check the result
    let test_result = Arc::new(AtomicBool::new(false));
    let error_result = test_result.clone();
    let thread_result = test_result.clone();
    tokio::run(
        sender_future
            .select(receiver_future)
            .timeout(Duration::from_millis(1000))
            .map_err(move |_| error_result.store(false, Relaxed))
            .map(move |result| {
                thread_result.store(result.0, Relaxed);
            }),
    );
    assert!(test_result.load(Relaxed));
}

#[test]
// Tests a Goodbye RPC message
fn test_goodbye_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(&log);

    // Goodbye Request
    let rpc_request = RPCRequest::Goodbye(GoodbyeReason::ClientShutdown);

    let sender_request = rpc_request.clone();
    let sender_log = log.clone();

    // build the sender future
    let sender_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match sender.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::PeerDialed(peer_id))) => {
                    // Send a Goodbye request
                    warn!(sender_log, "Sender sending RPC request");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(1, sender_request.clone()));
                }
                Async::Ready(Some(_)) => {}
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    // build the receiver future
    let receiver_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match receiver.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::RPC(_, event))) => match event {
                    // Should receive the sent RPC request
                    RPCEvent::Request(id, request) => {
                        if request == rpc_request {
                            assert_eq!(id, 0);
                            assert_eq!(rpc_request.clone(), request);
                            // receives the goodbye. Nothing left to do
                            return Ok(Async::Ready(true));
                        }
                    }
                    _ => panic!("Received invalid RPC message"),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            }
        }
    });

    // execute the futures and check the result
    let test_result = Arc::new(AtomicBool::new(false));
    let error_result = test_result.clone();
    let thread_result = test_result.clone();
    tokio::run(
        sender_future
            .select(receiver_future)
            .timeout(Duration::from_millis(1000))
            .map_err(move |_| error_result.store(false, Relaxed))
            .map(move |result| {
                thread_result.store(result.0, Relaxed);
            }),
    );
    assert!(test_result.load(Relaxed));
}
*/
