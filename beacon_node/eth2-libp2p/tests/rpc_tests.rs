#![cfg(test)]
use eth2_libp2p::rpc::{RPCRequest, StatusMessage};
use eth2_libp2p::{Libp2pEvent, RPCEvent};
use futures;
use futures::prelude::*;
use types::{Epoch, Hash256, Slot};

mod common;

#[test]
fn test_rpc() {
    let mut nodes = common::build_full_mesh(2, None);
    // Random rpc message
    let rpc_request = RPCRequest::Status(StatusMessage {
        fork_version: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for node in nodes.iter_mut() {
            loop {
                match node.poll().unwrap() {
                    Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id))) => {
                        // Send an rpc message
                        node.swarm
                            .send_rpc(peer_id, RPCEvent::Request(1, rpc_request.clone()));
                    }
                    Async::Ready(Some(Libp2pEvent::RPC(_, event))) => match event {
                        // Should receive sent rpc message
                        RPCEvent::Request(id, request) => {
                            assert_eq!(id, 1);
                            assert_eq!(rpc_request.clone(), request);
                            return Ok(Async::Ready(()));
                        }
                        _ => panic!("Received incorrect rpc message"),
                    },
                    Async::Ready(Some(_)) => (),
                    Async::Ready(None) | Async::NotReady => break,
                }
            }
        }
        Ok(Async::NotReady)
    }))
}
