#![cfg(test)]

mod common;

use common::Protocol;
use lighthouse_network::rpc::methods::*;
use lighthouse_network::service::api_types::AppRequestId;
use lighthouse_network::{rpc::max_rpc_size, NetworkEvent, ReportSource, Request, Response};
use slog::{debug, warn, Level};
use ssz::Encode;
use ssz_types::VariableList;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::time::sleep;
use types::{
    BeaconBlock, BeaconBlockAltair, BeaconBlockBase, BeaconBlockBellatrix, BlobSidecar, ChainSpec,
    EmptyBlock, Epoch, EthSpec, ForkContext, ForkName, Hash256, MinimalEthSpec, Signature,
    SignedBeaconBlock, Slot,
};

type E = MinimalEthSpec;

/// Bellatrix block with length < max_rpc_size.
fn bellatrix_block_small(fork_context: &ForkContext, spec: &ChainSpec) -> BeaconBlock<E> {
    let mut block = BeaconBlockBellatrix::<E>::empty(spec);
    let tx = VariableList::from(vec![0; 1024]);
    let txs = VariableList::from(std::iter::repeat(tx).take(5000).collect::<Vec<_>>());

    block.body.execution_payload.execution_payload.transactions = txs;

    let block = BeaconBlock::Bellatrix(block);
    assert!(block.ssz_bytes_len() <= max_rpc_size(fork_context, spec.max_chunk_size as usize));
    block
}

/// Bellatrix block with length > MAX_RPC_SIZE.
/// The max limit for a bellatrix block is in the order of ~16GiB which wouldn't fit in memory.
/// Hence, we generate a bellatrix block just greater than `MAX_RPC_SIZE` to test rejection on the rpc layer.
fn bellatrix_block_large(fork_context: &ForkContext, spec: &ChainSpec) -> BeaconBlock<E> {
    let mut block = BeaconBlockBellatrix::<E>::empty(spec);
    let tx = VariableList::from(vec![0; 1024]);
    let txs = VariableList::from(std::iter::repeat(tx).take(100000).collect::<Vec<_>>());

    block.body.execution_payload.execution_payload.transactions = txs;

    let block = BeaconBlock::Bellatrix(block);
    assert!(block.ssz_bytes_len() > max_rpc_size(fork_context, spec.max_chunk_size as usize));
    block
}

// Tests the STATUS RPC message
#[test]
#[allow(clippy::single_match)]
fn test_tcp_status_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let rt = Arc::new(Runtime::new().unwrap());

    let log = common::build_log(log_level, enable_logging);

    let spec = E::default_spec();

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Base,
            &spec,
            Protocol::Tcp,
        )
        .await;

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
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        id: AppRequestId::Router,
                        response,
                    } => {
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
                    NetworkEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    } => {
                        if request == rpc_request {
                            // send the response
                            debug!(log, "Receiver Received");
                            receiver.send_response(peer_id, id, rpc_response.clone());
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        };

        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(30)) => {
                panic!("Future timed out");
            }
        }
    })
}

// Tests a streamed BlocksByRange RPC Message
#[test]
#[allow(clippy::single_match)]
fn test_tcp_blocks_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 6;

    let log = common::build_log(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = E::default_spec();

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Bellatrix,
            &spec,
            Protocol::Tcp,
        )
        .await;

        // BlocksByRange Request
        let rpc_request = Request::BlocksByRange(BlocksByRangeRequest::new(0, messages_to_send));

        let spec = E::default_spec();

        // BlocksByRange Response
        let full_block = BeaconBlock::Base(BeaconBlockBase::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_base = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

        let full_block = BeaconBlock::Altair(BeaconBlockAltair::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_altair = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

        let full_block = bellatrix_block_small(&common::fork_context(ForkName::Bellatrix), &spec);
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_bellatrix_small =
            Response::BlocksByRange(Some(Arc::new(signed_full_block)));

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        id: _,
                        response,
                    } => {
                        warn!(log, "Sender received a response");
                        match response {
                            Response::BlocksByRange(Some(_)) => {
                                if messages_received < 2 {
                                    assert_eq!(response, rpc_response_base.clone());
                                } else if messages_received < 4 {
                                    assert_eq!(response, rpc_response_altair.clone());
                                } else {
                                    assert_eq!(response, rpc_response_bellatrix_small.clone());
                                }
                                messages_received += 1;
                                warn!(log, "Chunk received");
                            }
                            Response::BlocksByRange(None) => {
                                // should be exactly `messages_to_send` messages before terminating
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
                    NetworkEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    } => {
                        if request == rpc_request {
                            // send the response
                            warn!(log, "Receiver got request");
                            for i in 0..messages_to_send {
                                // Send first third of responses as base blocks,
                                // second as altair and third as bellatrix.
                                let rpc_response = if i < 2 {
                                    rpc_response_base.clone()
                                } else if i < 4 {
                                    rpc_response_altair.clone()
                                } else {
                                    rpc_response_bellatrix_small.clone()
                                };
                                receiver.send_response(peer_id, id, rpc_response.clone());
                            }
                            // send the stream termination
                            receiver.send_response(peer_id, id, Response::BlocksByRange(None));
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        };

        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(30)) => {
                    panic!("Future timed out");
            }
        }
    })
}

// Tests a streamed BlobsByRange RPC Message
#[test]
#[allow(clippy::single_match)]
fn test_blobs_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let slot_count = 32;
    let messages_to_send = 34;

    let log = common::build_log(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    rt.block_on(async {
        // get sender/receiver
        let spec = E::default_spec();
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Deneb,
            &spec,
            Protocol::Tcp,
        )
        .await;

        // BlobsByRange Request
        let rpc_request = Request::BlobsByRange(BlobsByRangeRequest {
            start_slot: 0,
            count: slot_count,
        });

        // BlocksByRange Response
        let blob = BlobSidecar::<E>::empty();

        let rpc_response = Response::BlobsByRange(Some(Arc::new(blob)));

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        id: _,
                        response,
                    } => {
                        warn!(log, "Sender received a response");
                        match response {
                            Response::BlobsByRange(Some(_)) => {
                                assert_eq!(response, rpc_response.clone());
                                messages_received += 1;
                                warn!(log, "Chunk received");
                            }
                            Response::BlobsByRange(None) => {
                                // should be exactly `messages_to_send` messages before terminating
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
                    NetworkEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    } => {
                        if request == rpc_request {
                            // send the response
                            warn!(log, "Receiver got request");
                            for _ in 0..messages_to_send {
                                // Send first third of responses as base blocks,
                                // second as altair and third as bellatrix.
                                receiver.send_response(peer_id, id, rpc_response.clone());
                            }
                            // send the stream termination
                            receiver.send_response(peer_id, id, Response::BlobsByRange(None));
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        };

        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(30)) => {
                    panic!("Future timed out");
            }
        }
    })
}

// Tests rejection of blocks over `MAX_RPC_SIZE`.
#[test]
#[allow(clippy::single_match)]
fn test_tcp_blocks_by_range_over_limit() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 5;

    let log = common::build_log(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = E::default_spec();

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Bellatrix,
            &spec,
            Protocol::Tcp,
        )
        .await;

        // BlocksByRange Request
        let rpc_request = Request::BlocksByRange(BlocksByRangeRequest::new(0, messages_to_send));

        // BlocksByRange Response
        let full_block = bellatrix_block_large(&common::fork_context(ForkName::Bellatrix), &spec);
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_bellatrix_large =
            Response::BlocksByRange(Some(Arc::new(signed_full_block)));

        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    // The request will fail because the sender will refuse to send anything > MAX_RPC_SIZE
                    NetworkEvent::RPCFailed { id, .. } => {
                        assert!(matches!(id, AppRequestId::Router));
                        return;
                    }
                    _ => {} // Ignore other behaviour events
                }
            }
        };

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    } => {
                        if request == rpc_request {
                            // send the response
                            warn!(log, "Receiver got request");
                            for _ in 0..messages_to_send {
                                let rpc_response = rpc_response_bellatrix_large.clone();
                                receiver.send_response(peer_id, id, rpc_response.clone());
                            }
                            // send the stream termination
                            receiver.send_response(peer_id, id, Response::BlocksByRange(None));
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        };

        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(30)) => {
                    panic!("Future timed out");
            }
        }
    })
}

// Tests that a streamed BlocksByRange RPC Message terminates when all expected chunks were received
#[test]
fn test_tcp_blocks_by_range_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 10;
    let extra_messages_to_send = 10;

    let log = common::build_log(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = E::default_spec();

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Base,
            &spec,
            Protocol::Tcp,
        )
        .await;

        // BlocksByRange Request
        let rpc_request = Request::BlocksByRange(BlocksByRangeRequest::new(0, messages_to_send));

        // BlocksByRange Response
        let spec = E::default_spec();
        let empty_block = BeaconBlock::empty(&spec);
        let empty_signed = SignedBeaconBlock::from_block(empty_block, Signature::empty());
        let rpc_response = Response::BlocksByRange(Some(Arc::new(empty_signed)));

        // keep count of the number of messages received
        let mut messages_received: u64 = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        id: _,
                        response,
                    } =>
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
                    Box::pin(tokio::time::sleep(Duration::from_secs(1))),
                )
                .await
                {
                    futures::future::Either::Left((
                        NetworkEvent::RequestReceived {
                            peer_id,
                            id,
                            request,
                        },
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
                    receiver.send_response(*peer_id, *stream_id, rpc_response.clone());
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
            _ = sleep(Duration::from_secs(30)) => {
                panic!("Future timed out");
            }
        }
    })
}

// Tests an empty response to a BlocksByRange RPC Message
#[test]
#[allow(clippy::single_match)]
fn test_tcp_blocks_by_range_single_empty_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);
    let rt = Arc::new(Runtime::new().unwrap());

    let spec = E::default_spec();

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Base,
            &spec,
            Protocol::Tcp,
        )
        .await;

        // BlocksByRange Request
        let rpc_request = Request::BlocksByRange(BlocksByRangeRequest::new(0, 10));

        // BlocksByRange Response
        let spec = E::default_spec();
        let empty_block = BeaconBlock::empty(&spec);
        let empty_signed = SignedBeaconBlock::from_block(empty_block, Signature::empty());
        let rpc_response = Response::BlocksByRange(Some(Arc::new(empty_signed)));

        let messages_to_send = 1;

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        id: AppRequestId::Router,
                        response,
                    } => match response {
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
                    NetworkEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    } => {
                        if request == rpc_request {
                            // send the response
                            warn!(log, "Receiver got request");

                            for _ in 1..=messages_to_send {
                                receiver.send_response(peer_id, id, rpc_response.clone());
                            }
                            // send the stream termination
                            receiver.send_response(peer_id, id, Response::BlocksByRange(None));
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        };
        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(20)) => {
                panic!("Future timed out");
            }
        }
    })
}

// Tests a streamed, chunked BlocksByRoot RPC Message
// The size of the response is a full `BeaconBlock`
// which is greater than the Snappy frame size. Hence, this test
// serves to test the snappy framing format as well.
#[test]
#[allow(clippy::single_match)]
fn test_tcp_blocks_by_root_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 6;

    let log = common::build_log(log_level, enable_logging);
    let spec = E::default_spec();

    let rt = Arc::new(Runtime::new().unwrap());
    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Bellatrix,
            &spec,
            Protocol::Tcp,
        )
        .await;

        // BlocksByRoot Request
        let rpc_request = Request::BlocksByRoot(BlocksByRootRequest::new(
            vec![
                Hash256::from_low_u64_be(0),
                Hash256::from_low_u64_be(0),
                Hash256::from_low_u64_be(0),
                Hash256::from_low_u64_be(0),
                Hash256::from_low_u64_be(0),
                Hash256::from_low_u64_be(0),
            ],
            &spec,
        ));

        // BlocksByRoot Response
        let full_block = BeaconBlock::Base(BeaconBlockBase::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_base = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

        let full_block = BeaconBlock::Altair(BeaconBlockAltair::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_altair = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

        let full_block = bellatrix_block_small(&common::fork_context(ForkName::Bellatrix), &spec);
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_bellatrix_small =
            Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        id: AppRequestId::Router,
                        response,
                    } => match response {
                        Response::BlocksByRoot(Some(_)) => {
                            if messages_received < 2 {
                                assert_eq!(response, rpc_response_base.clone());
                            } else if messages_received < 4 {
                                assert_eq!(response, rpc_response_altair.clone());
                            } else {
                                assert_eq!(response, rpc_response_bellatrix_small.clone());
                            }
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
                    NetworkEvent::RequestReceived {
                        peer_id,
                        id,
                        request,
                    } => {
                        if request == rpc_request {
                            // send the response
                            debug!(log, "Receiver got request");

                            for i in 0..messages_to_send {
                                // Send equal base, altair and bellatrix blocks
                                let rpc_response = if i < 2 {
                                    rpc_response_base.clone()
                                } else if i < 4 {
                                    rpc_response_altair.clone()
                                } else {
                                    rpc_response_bellatrix_small.clone()
                                };
                                receiver.send_response(peer_id, id, rpc_response);
                                debug!(log, "Sending message");
                            }
                            // send the stream termination
                            receiver.send_response(peer_id, id, Response::BlocksByRange(None));
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
            _ = sleep(Duration::from_secs(30)) => {
                    panic!("Future timed out");
            }
        }
    })
}

// Tests a streamed, chunked BlocksByRoot RPC Message terminates when all expected reponses have been received
#[test]
fn test_tcp_blocks_by_root_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send: u64 = 10;
    let extra_messages_to_send: u64 = 10;

    let log = common::build_log(log_level, enable_logging);
    let spec = E::default_spec();

    let rt = Arc::new(Runtime::new().unwrap());
    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            &log,
            ForkName::Base,
            &spec,
            Protocol::Tcp,
        )
        .await;

        // BlocksByRoot Request
        let rpc_request = Request::BlocksByRoot(BlocksByRootRequest::new(
            vec![
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
            ],
            &spec,
        ));

        // BlocksByRoot Response
        let full_block = BeaconBlock::Base(BeaconBlockBase::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!(log, "Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        id: AppRequestId::Router,
                        response,
                    } => {
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
                    Box::pin(tokio::time::sleep(Duration::from_secs(1))),
                )
                .await
                {
                    futures::future::Either::Left((
                        NetworkEvent::RequestReceived {
                            peer_id,
                            id,
                            request,
                        },
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
                    receiver.send_response(*peer_id, *stream_id, rpc_response.clone());
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
            _ = sleep(Duration::from_secs(30)) => {
                panic!("Future timed out");
            }
        }
    })
}

/// Establishes a pair of nodes and disconnects the pair based on the selected protocol via an RPC
/// Goodbye message.
fn goodbye_test(log_level: Level, enable_logging: bool, protocol: Protocol) {
    let log = common::build_log(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = E::default_spec();

    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) =
            common::build_node_pair(Arc::downgrade(&rt), &log, ForkName::Base, &spec, protocol)
                .await;

        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a goodbye and disconnect
                        debug!(log, "Sending RPC");
                        sender.goodbye_peer(
                            &peer_id,
                            GoodbyeReason::IrrelevantNetwork,
                            ReportSource::SyncService,
                        );
                    }
                    NetworkEvent::PeerDisconnected(_) => {
                        return;
                    }
                    _ => {} // Ignore other RPC messages
                }
            }
        };

        // build the receiver future
        let receiver_future = async {
            loop {
                if let NetworkEvent::PeerDisconnected(_) = receiver.next_event().await {
                    // Should receive sent RPC request
                    return;
                }
            }
        };

        let total_future = futures::future::join(sender_future, receiver_future);

        tokio::select! {
            _ = total_future => {}
            _ = sleep(Duration::from_secs(30)) => {
                panic!("Future timed out");
            }
        }
    })
}

// Tests a Goodbye RPC message
#[test]
#[allow(clippy::single_match)]
fn tcp_test_goodbye_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;
    goodbye_test(log_level, enable_logging, Protocol::Tcp);
}

// Tests a Goodbye RPC message
#[test]
#[allow(clippy::single_match)]
fn quic_test_goodbye_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;
    goodbye_test(log_level, enable_logging, Protocol::Quic);
}
