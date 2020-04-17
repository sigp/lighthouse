#![cfg(test)]
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::*;
use eth2_libp2p::{BehaviourEvent, RPCEvent};
use slog::{warn, Level};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::prelude::*;
use types::{
    BeaconBlock, Epoch, EthSpec, Hash256, MinimalEthSpec, Signature, SignedBeaconBlock, Slot,
};

mod common;

type E = MinimalEthSpec;

#[test]
// Tests the STATUS RPC message
fn test_status_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let port = common::unused_port("tcp").unwrap();
    let (mut sender, mut receiver) = common::build_node_pair(&log, port);

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

    let sender_request = rpc_request.clone();
    let sender_log = log.clone();
    let sender_response = rpc_response.clone();

    // build the sender future
    let sender_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match sender.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::PeerDialed(peer_id))) => {
                    // Send a STATUS message
                    warn!(sender_log, "Sending RPC");
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(1, sender_request.clone()));
                }
                Async::Ready(Some(BehaviourEvent::RPC(_, event))) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response @ RPCErrorResponse::Success(_)) => {
                        if id == 1 {
                            warn!(sender_log, "Sender Received");
                            let response = {
                                match response {
                                    RPCErrorResponse::Success(r) => r,
                                    _ => unreachable!(),
                                }
                            };
                            assert_eq!(response, sender_response.clone());

                            warn!(sender_log, "Sender Completed");
                            return Ok(Async::Ready(true));
                        }
                    }
                    e => panic!("Received invalid RPC message {}", e),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    // build the receiver future
    let receiver_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match receiver.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::RPC(peer_id, event))) => match event {
                    // Should receive sent RPC request
                    RPCEvent::Request(id, request) => {
                        if request == rpc_request {
                            // send the response
                            warn!(log, "Receiver Received");
                            receiver.swarm.send_rpc(
                                peer_id,
                                RPCEvent::Response(
                                    id,
                                    RPCErrorResponse::Success(rpc_response.clone()),
                                ),
                            );
                        }
                    }
                    e => panic!("Received invalid RPC message {}", e),
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
// Tests a streamed BlocksByRange RPC Message
fn test_blocks_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let messages_to_send = 10;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let port = common::unused_port("tcp").unwrap();
    let (mut sender, mut receiver) = common::build_node_pair(&log, port);

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
                                RPCErrorResponse::Success(res) => {
                                    assert_eq!(res, sender_response.clone());
                                    *messages_received.lock().unwrap() += 1;
                                    warn!(sender_log, "Chunk received");
                                }
                                RPCErrorResponse::StreamTermination(
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
                                        RPCErrorResponse::Success(rpc_response.clone()),
                                    ),
                                );
                            }
                            // send the stream termination
                            receiver.swarm.send_rpc(
                                peer_id,
                                RPCEvent::Response(
                                    id,
                                    RPCErrorResponse::StreamTermination(
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
    let port = common::unused_port("tcp").unwrap();
    let (mut sender, mut receiver) = common::build_node_pair(&log, port);

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
                                RPCErrorResponse::Success(res) => {
                                    assert_eq!(res, sender_response.clone());
                                    *messages_received.lock().unwrap() += 1;
                                    warn!(sender_log, "Chunk received");
                                }
                                RPCErrorResponse::StreamTermination(
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
                                    RPCErrorResponse::Success(rpc_response.clone()),
                                ),
                            );
                            // send the stream termination
                            receiver.swarm.send_rpc(
                                peer_id,
                                RPCEvent::Response(
                                    id,
                                    RPCErrorResponse::StreamTermination(
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
    let port = common::unused_port("tcp").unwrap();
    let (mut sender, mut receiver) = common::build_node_pair(&log, port);

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
                            RPCErrorResponse::Success(res) => {
                                assert_eq!(res, sender_response.clone());
                                *messages_received.lock().unwrap() += 1;
                                warn!(sender_log, "Chunk received");
                            }
                            RPCErrorResponse::StreamTermination(
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
                                        RPCErrorResponse::Success(rpc_response.clone()),
                                    ),
                                );
                            }
                            // send the stream termination
                            receiver.swarm.send_rpc(
                                peer_id,
                                RPCEvent::Response(
                                    id,
                                    RPCErrorResponse::StreamTermination(
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
    let port = common::unused_port("tcp").unwrap();
    let (mut sender, mut receiver) = common::build_node_pair(&log, port);

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
