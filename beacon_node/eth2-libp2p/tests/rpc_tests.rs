#![cfg(test)]
use eth2_libp2p::rpc::*;
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::{Libp2pEvent, RPCEvent};
use slog::Level;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::prelude::*;
use types::{Epoch, Hash256, Slot};

mod common;

fn build_sender_receiver(start_port: u16) -> (LibP2PService, LibP2PService) {
    // set up the logging. The level and enabled or not
    let log = common::build_log(Level::Info, true);

    let mut nodes = common::build_full_mesh(log, 2, Some(start_port));
    (nodes.pop().unwrap(), nodes.pop().unwrap())
}

#[test]
fn test_status_rpc() {
    let (mut sender, mut receiver) = build_sender_receiver(10500);

    // Dummy STATUS RPC message
    let rpc_request = RPCRequest::Status(StatusMessage {
        fork_version: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    // Dummy STATUS RPC message
    let rpc_response = RPCResponse::Status(StatusMessage {
        fork_version: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    let sender_request = rpc_request.clone();
    let sender_response = rpc_response.clone();

    // build the sender future
    let sender_future = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            match sender.poll().unwrap() {
                Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id))) => {
                    // Send a STATUS message
                    sender
                        .swarm
                        .send_rpc(peer_id, RPCEvent::Request(1, sender_request.clone()));
                }
                Async::Ready(Some(Libp2pEvent::RPC(_, event))) => match event {
                    // Should receive the RPC response
                    RPCEvent::Response(id, response @ RPCErrorResponse::Success(_)) => {
                        assert_eq!(id, 1);

                        let response = {
                            match response {
                                RPCErrorResponse::Success(r) => r,
                                _ => unreachable!(),
                            }
                        };
                        assert_eq!(response, sender_response.clone());
                        return Ok(Async::Ready(()));
                    }
                    _ => panic!("Received invalid RPC message"),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    // this keeps track of when we have sent a response and can end the future if the swarm has
    // published the response.
    let requested_send = Arc::new(Mutex::new(true));

    // build the receiver future
    let receiver_future = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            match receiver.poll().unwrap() {
                Async::Ready(Some(Libp2pEvent::RPC(peer_id, event))) => match event {
                    // Should receive sent RPC request
                    RPCEvent::Request(id, request) => {
                        assert_eq!(id, 1);
                        assert_eq!(rpc_request.clone(), request);

                        // send the response
                        receiver.swarm.send_rpc(
                            peer_id,
                            RPCEvent::Response(1, RPCErrorResponse::Success(rpc_response.clone())),
                        );
                        // indicate message has been sent
                        *requested_send.lock().unwrap() = false;
                    }
                    _ => panic!("Received invalid RPC message"),
                },
                Async::Ready(Some(_)) => (),
                Async::Ready(None) | Async::NotReady => {
                    if *requested_send.lock().unwrap() {
                        // complete the future
                        return Ok(Async::Ready(()));
                    } else {
                        return Ok(Async::NotReady);
                    }
                }
            }
        }
    });

    // execute the futures and check the result
    let test_result = Arc::new(Mutex::new(true));
    let thread_result = test_result.clone();
    tokio::run(
        sender_future
            .select(receiver_future)
            .timeout(Duration::from_millis(100))
            .map_err(move |_| *thread_result.lock().unwrap() = false)
            .map(|_| ()),
    );
    assert!(*test_result.lock().unwrap());
}
