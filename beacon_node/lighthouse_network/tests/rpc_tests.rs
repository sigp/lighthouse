#![cfg(test)]

mod common;

use crate::common::spec_with_all_forks_enabled;
use common::{Protocol, build_tracing_subscriber};
use lighthouse_network::rpc::{RequestType, methods::*};
use lighthouse_network::service::api_types::AppRequestId;
use lighthouse_network::{NetworkEvent, ReportSource, Response};
use ssz::Encode;
use ssz_types::VariableList;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info_span, warn};
use types::{
    BeaconBlock, BeaconBlockAltair, BeaconBlockBase, BeaconBlockBellatrix, BeaconBlockHeader,
    BlobSidecar, ChainSpec, DataColumnSidecar, DataColumnsByRootIdentifier, EmptyBlock, Epoch,
    EthSpec, FixedBytesExtended, ForkName, Hash256, KzgCommitment, KzgProof, MinimalEthSpec,
    RuntimeVariableList, Signature, SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
};

type E = MinimalEthSpec;

/// Bellatrix block with length < max_rpc_size.
fn bellatrix_block_small(spec: &ChainSpec) -> BeaconBlock<E> {
    let mut block = BeaconBlockBellatrix::<E>::empty(spec);
    let tx = VariableList::from(vec![0; 1024]);
    let txs = VariableList::from(std::iter::repeat_n(tx, 5000).collect::<Vec<_>>());

    block.body.execution_payload.execution_payload.transactions = txs;

    let block = BeaconBlock::Bellatrix(block);
    assert!(block.ssz_bytes_len() <= spec.max_payload_size as usize);
    block
}

/// Bellatrix block with length > MAX_RPC_SIZE.
/// The max limit for a bellatrix block is in the order of ~16GiB which wouldn't fit in memory.
/// Hence, we generate a bellatrix block just greater than `MAX_RPC_SIZE` to test rejection on the rpc layer.
fn bellatrix_block_large(spec: &ChainSpec) -> BeaconBlock<E> {
    let mut block = BeaconBlockBellatrix::<E>::empty(spec);
    let tx = VariableList::from(vec![0; 1024]);
    let txs = VariableList::from(std::iter::repeat_n(tx, 100000).collect::<Vec<_>>());

    block.body.execution_payload.execution_payload.transactions = txs;

    let block = BeaconBlock::Bellatrix(block);
    assert!(block.ssz_bytes_len() > spec.max_payload_size as usize);
    block
}

// Tests the STATUS RPC message
#[test]
#[allow(clippy::single_match)]
fn test_tcp_status_rpc() {
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = Arc::new(spec_with_all_forks_enabled());

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Base,
            spec,
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // Dummy STATUS RPC message
        let rpc_request = RequestType::Status(StatusMessage::V2(StatusMessageV2 {
            fork_digest: [0; 4],
            finalized_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::zero(),
            head_slot: Slot::new(1),
            earliest_available_slot: Slot::new(0),
        }));

        // Dummy STATUS RPC message
        let rpc_response = Response::Status(StatusMessage::V2(StatusMessageV2 {
            fork_digest: [0; 4],
            finalized_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::zero(),
            head_slot: Slot::new(1),
            earliest_available_slot: Slot::new(0),
        }));

        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: AppRequestId::Router,
                        response,
                    } => {
                        // Should receive the RPC response
                        debug!("Sender Received");
                        assert_eq!(response, rpc_response.clone());
                        debug!("Sender Completed");
                        return;
                    }
                    _ => {}
                }
            }
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            debug!("Receiver Received");
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                rpc_response.clone(),
                            );
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));

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
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let messages_to_send = 6;

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = Arc::new(spec_with_all_forks_enabled());

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Bellatrix,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // BlocksByRange Request
        let rpc_request =
            RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2 {
                start_slot: 0,
                count: messages_to_send,
                step: 1,
            }));

        // BlocksByRange Response
        let full_block = BeaconBlock::Base(BeaconBlockBase::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_base = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

        let full_block = BeaconBlock::Altair(BeaconBlockAltair::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_altair = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

        let full_block = bellatrix_block_small(&spec);
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
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: _,
                        response,
                    } => {
                        warn!("Sender received a response");
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
                                warn!("Chunk received");
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
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            warn!("Receiver got request");
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
                                receiver.send_response(
                                    peer_id,
                                    inbound_request_id,
                                    rpc_response.clone(),
                                );
                            }
                            // send the stream termination
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::BlocksByRange(None),
                            );
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));

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
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let slot_count = 32;
    let messages_to_send = 34;

    let rt = Arc::new(Runtime::new().unwrap());

    rt.block_on(async {
        // get sender/receiver
        let spec = Arc::new(spec_with_all_forks_enabled());
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Deneb,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // BlobsByRange Request
        let deneb_slot = spec
            .deneb_fork_epoch
            .expect("deneb must be scheduled")
            .start_slot(E::slots_per_epoch());
        let rpc_request = RequestType::BlobsByRange(BlobsByRangeRequest {
            start_slot: deneb_slot.as_u64(),
            count: slot_count,
        });

        // BlobsByRange Response
        let mut blob = BlobSidecar::<E>::empty();
        blob.signed_block_header.message.slot = deneb_slot;

        let rpc_response = Response::BlobsByRange(Some(Arc::new(blob)));

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: _,
                        response,
                    } => {
                        warn!("Sender received a response");
                        match response {
                            Response::BlobsByRange(Some(_)) => {
                                assert_eq!(response, rpc_response.clone());
                                messages_received += 1;
                                warn!("Chunk received");
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
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            warn!("Receiver got request");
                            for _ in 0..messages_to_send {
                                // Send first third of responses as base blocks,
                                // second as altair and third as bellatrix.
                                receiver.send_response(
                                    peer_id,
                                    inbound_request_id,
                                    rpc_response.clone(),
                                );
                            }
                            // send the stream termination
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::BlobsByRange(None),
                            );
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));

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
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let messages_to_send = 5;

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = Arc::new(spec_with_all_forks_enabled());

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Bellatrix,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // BlocksByRange Request
        let rpc_request =
            RequestType::BlocksByRange(OldBlocksByRangeRequest::V1(OldBlocksByRangeRequestV1 {
                start_slot: 0,
                count: messages_to_send,
                step: 1,
            }));

        // BlocksByRange Response
        let full_block = bellatrix_block_large(&spec);
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_bellatrix_large =
            Response::BlocksByRange(Some(Arc::new(signed_full_block)));

        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a STATUS message
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    // The request will fail because the sender will refuse to send anything > MAX_RPC_SIZE
                    NetworkEvent::RPCFailed { app_request_id, .. } => {
                        assert!(matches!(app_request_id, AppRequestId::Router));
                        return;
                    }
                    _ => {} // Ignore other behaviour events
                }
            }
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            warn!("Receiver got request");
                            for _ in 0..messages_to_send {
                                let rpc_response = rpc_response_bellatrix_large.clone();
                                receiver.send_response(
                                    peer_id,
                                    inbound_request_id,
                                    rpc_response.clone(),
                                );
                            }
                            // send the stream termination
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::BlocksByRange(None),
                            );
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));

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
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let messages_to_send = 10;
    let extra_messages_to_send = 10;

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = Arc::new(spec_with_all_forks_enabled());

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Base,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // BlocksByRange Request
        let rpc_request =
            RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2 {
                start_slot: 0,
                count: messages_to_send,
                step: 1,
            }));

        // BlocksByRange Response
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
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: _,
                        response,
                    } =>
                    // Should receive the RPC response
                    {
                        debug!("Sender received a response");
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
        }
        .instrument(info_span!("Sender"));

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
                            inbound_request_id,
                            request_type,
                        },
                        _,
                    )) => {
                        if request_type == rpc_request {
                            // send the response
                            warn!("Receiver got request");
                            message_info = Some((peer_id, inbound_request_id));
                        }
                    }
                    futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                    _ => continue,
                }

                // if we need to send messages send them here. This will happen after a delay
                if let Some((peer_id, inbound_request_id)) = &message_info {
                    messages_sent += 1;
                    receiver.send_response(*peer_id, *inbound_request_id, rpc_response.clone());
                    debug!("Sending message {}", messages_sent);
                    if messages_sent == messages_to_send + extra_messages_to_send {
                        // stop sending messages
                        return;
                    }
                }
            }
        }
        .instrument(info_span!("Receiver"));

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
    // Set up the logging.
    let log_level = "trace";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = Arc::new(spec_with_all_forks_enabled());

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Base,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // BlocksByRange Request
        let rpc_request =
            RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2 {
                start_slot: 0,
                count: 10,
                step: 1,
            }));

        // BlocksByRange Response
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
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: AppRequestId::Router,
                        response,
                    } => match response {
                        Response::BlocksByRange(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                            warn!("Chunk received");
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
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            warn!("Receiver got request");

                            for _ in 1..=messages_to_send {
                                receiver.send_response(
                                    peer_id,
                                    inbound_request_id,
                                    rpc_response.clone(),
                                );
                            }
                            // send the stream termination
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::BlocksByRange(None),
                            );
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));
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
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let messages_to_send = 6;

    let spec = Arc::new(spec_with_all_forks_enabled());
    let current_fork_name = ForkName::Bellatrix;

    let rt = Arc::new(Runtime::new().unwrap());
    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            current_fork_name,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // BlocksByRoot Request
        let rpc_request =
            RequestType::BlocksByRoot(BlocksByRootRequest::V2(BlocksByRootRequestV2 {
                block_roots: RuntimeVariableList::new(
                    vec![
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                    ],
                    spec.max_request_blocks(current_fork_name),
                )
                .unwrap(),
            }));

        // BlocksByRoot Response
        let full_block = BeaconBlock::Base(BeaconBlockBase::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_base = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

        let full_block = BeaconBlock::Altair(BeaconBlockAltair::<E>::full(&spec));
        let signed_full_block = SignedBeaconBlock::from_block(full_block, Signature::empty());
        let rpc_response_altair = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

        let full_block = bellatrix_block_small(&spec);
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
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: AppRequestId::Router,
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
                            debug!("Chunk received");
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
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            debug!("Receiver got request");

                            for i in 0..messages_to_send {
                                // Send equal base, altair and bellatrix blocks
                                let rpc_response = if i < 2 {
                                    rpc_response_base.clone()
                                } else if i < 4 {
                                    rpc_response_altair.clone()
                                } else {
                                    rpc_response_bellatrix_small.clone()
                                };
                                receiver.send_response(peer_id, inbound_request_id, rpc_response);
                                debug!("Sending message");
                            }
                            // send the stream termination
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::BlocksByRange(None),
                            );
                            debug!("Send stream term");
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));
        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(300)) => {
                    panic!("Future timed out");
            }
        }
    })
}

#[test]
#[allow(clippy::single_match)]
fn test_tcp_columns_by_root_chunked_rpc() {
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);
    let num_of_columns = E::number_of_columns();
    let messages_to_send = 32 * num_of_columns;

    let spec = Arc::new(spec_with_all_forks_enabled());
    let current_fork_name = ForkName::Fulu;

    let rt = Arc::new(Runtime::new().unwrap());
    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            current_fork_name,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // DataColumnsByRootRequest Request

        let max_request_blocks = spec.max_request_blocks(current_fork_name);
        let req = DataColumnsByRootRequest::new(
            vec![
                DataColumnsByRootIdentifier {
                    block_root: Hash256::zero(),
                    columns: VariableList::new(
                        (0..E::number_of_columns() as u64).collect::<Vec<_>>()
                    )
                    .unwrap(),
                };
                max_request_blocks
            ],
            max_request_blocks,
        )
        .unwrap();
        let req_bytes = req.data_column_ids.as_ssz_bytes();
        let req_decoded = DataColumnsByRootRequest {
            data_column_ids: <RuntimeVariableList<DataColumnsByRootIdentifier<E>>>::from_ssz_bytes(
                &req_bytes,
                spec.max_request_blocks(current_fork_name),
            )
            .unwrap(),
        };
        assert_eq!(req, req_decoded);
        let rpc_request = RequestType::DataColumnsByRoot(req);

        // DataColumnsByRoot Response
        let data_column = Arc::new(DataColumnSidecar {
            index: 1,
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot: 320u64.into(),
                    proposer_index: 1,
                    parent_root: Hash256::zero(),
                    state_root: Hash256::zero(),
                    body_root: Hash256::zero(),
                },
                signature: Signature::empty(),
            },
            column: vec![vec![0; E::bytes_per_blob()].into()].into(),
            kzg_commitments: vec![KzgCommitment::empty_for_testing()].into(),
            kzg_proofs: vec![KzgProof::empty()].into(),
            kzg_commitments_inclusion_proof: vec![
                Hash256::zero();
                E::kzg_commitments_inclusion_proof_depth()
            ]
            .into(),
        });

        let rpc_response = Response::DataColumnsByRoot(Some(data_column.clone()));

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        tracing::info!("Sending RPC");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: AppRequestId::Router,
                        response,
                    } => match response {
                        Response::DataColumnsByRoot(Some(sidecar)) => {
                            assert_eq!(sidecar, data_column.clone());
                            messages_received += 1;
                            tracing::info!("Chunk received");
                        }
                        Response::DataColumnsByRoot(None) => {
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
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            tracing::info!("Receiver got request");

                            for _ in 0..messages_to_send {
                                receiver.send_response(
                                    peer_id,
                                    inbound_request_id,
                                    rpc_response.clone(),
                                );
                                tracing::info!("Sending message");
                            }
                            // send the stream termination
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::DataColumnsByRoot(None),
                            );
                            tracing::info!("Send stream term");
                        }
                    }
                    e => {
                        tracing::info!(?e, "Got event");
                    } // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));
        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(300)) => {
                    panic!("Future timed out");
            }
        }
    })
}

#[test]
#[allow(clippy::single_match)]
fn test_tcp_columns_by_range_chunked_rpc() {
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let messages_to_send = 32;

    let spec = Arc::new(spec_with_all_forks_enabled());
    let current_fork_name = ForkName::Fulu;

    let rt = Arc::new(Runtime::new().unwrap());
    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            current_fork_name,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // DataColumnsByRange Request
        let rpc_request = RequestType::DataColumnsByRange(DataColumnsByRangeRequest {
            start_slot: 320,
            count: 32,
            columns: (0..E::number_of_columns() as u64).collect(),
        });

        // DataColumnsByRange Response
        let data_column = Arc::new(DataColumnSidecar {
            index: 1,
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot: 320u64.into(),
                    proposer_index: 1,
                    parent_root: Hash256::zero(),
                    state_root: Hash256::zero(),
                    body_root: Hash256::zero(),
                },
                signature: Signature::empty(),
            },
            column: vec![vec![0; E::bytes_per_blob()].into()].into(),
            kzg_commitments: vec![KzgCommitment::empty_for_testing()].into(),
            kzg_proofs: vec![KzgProof::empty()].into(),
            kzg_commitments_inclusion_proof: vec![
                Hash256::zero();
                E::kzg_commitments_inclusion_proof_depth()
            ]
            .into(),
        });

        let rpc_response = Response::DataColumnsByRange(Some(data_column.clone()));

        // keep count of the number of messages received
        let mut messages_received = 0;
        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        tracing::info!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: AppRequestId::Router,
                        response,
                    } => match response {
                        Response::DataColumnsByRange(Some(sidecar)) => {
                            assert_eq!(sidecar, data_column.clone());
                            messages_received += 1;
                            tracing::info!("Chunk received");
                        }
                        Response::DataColumnsByRange(None) => {
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
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                match receiver.next_event().await {
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    } => {
                        if request_type == rpc_request {
                            // send the response
                            tracing::info!("Receiver got request");

                            for _ in 0..messages_to_send {
                                receiver.send_response(
                                    peer_id,
                                    inbound_request_id,
                                    rpc_response.clone(),
                                );
                                tracing::info!("Sending message");
                            }
                            // send the stream termination
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::DataColumnsByRange(None),
                            );
                            tracing::info!("Send stream term");
                        }
                    }
                    _ => {} // Ignore other events
                }
            }
        }
        .instrument(info_span!("Receiver"));
        tokio::select! {
            _ = sender_future => {}
            _ = receiver_future => {}
            _ = sleep(Duration::from_secs(300)) => {
                    panic!("Future timed out");
            }
        }
    })
}

// Tests a streamed, chunked BlocksByRoot RPC Message terminates when all expected reponses have been received
#[test]
fn test_tcp_blocks_by_root_chunked_rpc_terminates_correctly() {
    // Set up the logging.
    let log_level = "debug";
    let enable_logging = true;
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let messages_to_send: u64 = 10;
    let extra_messages_to_send: u64 = 10;

    let spec = Arc::new(spec_with_all_forks_enabled());
    let current_fork = ForkName::Base;

    let rt = Arc::new(Runtime::new().unwrap());
    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            current_fork,
            spec.clone(),
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // BlocksByRoot Request
        let rpc_request =
            RequestType::BlocksByRoot(BlocksByRootRequest::V2(BlocksByRootRequestV2 {
                block_roots: RuntimeVariableList::new(
                    vec![
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                        Hash256::zero(),
                    ],
                    spec.max_request_blocks(current_fork),
                )
                .unwrap(),
            }));

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
                        debug!("Sending RPC");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id: _,
                        app_request_id: AppRequestId::Router,
                        response,
                    } => {
                        debug!("Sender received a response");
                        match response {
                            Response::BlocksByRoot(Some(_)) => {
                                assert_eq!(response, rpc_response.clone());
                                messages_received += 1;
                                debug!("Chunk received");
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
        }
        .instrument(info_span!("Sender"));

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
                            inbound_request_id,
                            request_type,
                        },
                        _,
                    )) => {
                        if request_type == rpc_request {
                            // send the response
                            warn!("Receiver got request");
                            message_info = Some((peer_id, inbound_request_id));
                        }
                    }
                    futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                    _ => continue,
                }

                // if we need to send messages send them here. This will happen after a delay
                if let Some((peer_id, inbound_request_id)) = &message_info {
                    messages_sent += 1;
                    receiver.send_response(*peer_id, *inbound_request_id, rpc_response.clone());
                    debug!("Sending message {}", messages_sent);
                    if messages_sent == messages_to_send + extra_messages_to_send {
                        // stop sending messages
                        return;
                    }
                }
            }
        }
        .instrument(info_span!("Receiver"));

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
fn goodbye_test(log_level: &str, enable_logging: bool, protocol: Protocol) {
    // Set up the logging.
    let _subscriber = build_tracing_subscriber(log_level, enable_logging);

    let rt = Arc::new(Runtime::new().unwrap());

    let spec = Arc::new(spec_with_all_forks_enabled());

    // get sender/receiver
    rt.block_on(async {
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Base,
            spec,
            protocol,
            false,
            None,
        )
        .await;

        // build the sender future
        let sender_future = async {
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        // Send a goodbye and disconnect
                        debug!("Sending RPC");
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
        }
        .instrument(info_span!("Sender"));

        // build the receiver future
        let receiver_future = async {
            loop {
                if let NetworkEvent::PeerDisconnected(_) = receiver.next_event().await {
                    // Should receive sent RPC request
                    return;
                }
            }
        }
        .instrument(info_span!("Receiver"));

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
    let log_level = "debug";
    let enabled_logging = true;
    goodbye_test(log_level, enabled_logging, Protocol::Tcp);
}

// Tests a Goodbye RPC message
#[test]
#[allow(clippy::single_match)]
fn quic_test_goodbye_rpc() {
    let log_level = "debug";
    let enabled_logging = true;
    goodbye_test(log_level, enabled_logging, Protocol::Quic);
}

// Test that the receiver delays the responses during response rate-limiting.
#[test]
fn test_delayed_rpc_response() {
    // Set up the logging.
    let _subscriber = build_tracing_subscriber("debug", true);
    let rt = Arc::new(Runtime::new().unwrap());
    let spec = Arc::new(spec_with_all_forks_enabled());

    // Allow 1 token to be use used every 3 seconds.
    const QUOTA_SEC: u64 = 3;

    rt.block_on(async {
        // get sender/receiver
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Base,
            spec,
            Protocol::Tcp,
            false,
            // Configure a quota for STATUS responses of 1 token every 3 seconds.
            Some(format!("status:1/{QUOTA_SEC}").parse().unwrap()),
        )
        .await;

        // Dummy STATUS RPC message
        let rpc_request = RequestType::Status(StatusMessage::V2(StatusMessageV2 {
            fork_digest: [0; 4],
            finalized_root: Hash256::from_low_u64_be(0),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::from_low_u64_be(0),
            head_slot: Slot::new(1),
            earliest_available_slot: Slot::new(0),
        }));

        // Dummy STATUS RPC message
        let rpc_response = Response::Status(StatusMessage::V2(StatusMessageV2 {
            fork_digest: [0; 4],
            finalized_root: Hash256::from_low_u64_be(0),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::from_low_u64_be(0),
            head_slot: Slot::new(1),
            earliest_available_slot: Slot::new(0),
        }));

        // build the sender future
        let sender_future = async {
            let mut request_id = 1;
            let mut request_sent_at = Instant::now();
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        debug!(%request_id, "Sending RPC request");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                        request_sent_at = Instant::now();
                    }
                    NetworkEvent::ResponseReceived {
                        peer_id,
                        app_request_id: _,
                        response,
                    } => {
                        debug!(%request_id, elapsed = ?request_sent_at.elapsed(), "Sender received response");
                        assert_eq!(response, rpc_response);

                        match request_id {
                            1 => {
                                // The first response is returned instantly.
                                assert!(request_sent_at.elapsed() < Duration::from_millis(100));
                            }
                            2..=5 => {
                                // The second and subsequent responses are delayed due to the response rate-limiter on the receiver side.
                                // Adding a slight margin to the elapsed time check to account for potential timing issues caused by system
                                // scheduling or execution delays during testing.
                                // https://github.com/sigp/lighthouse/issues/7466
                                let margin = 500;
                                assert!(
                                    request_sent_at.elapsed()
                                        > (Duration::from_secs(QUOTA_SEC)
                                            - Duration::from_millis(margin))
                                );
                                if request_id == 5 {
                                    // End the test
                                    return;
                                }
                            }
                            _ => unreachable!(),
                        }

                        request_id += 1;
                        debug!(%request_id, "Sending RPC request");
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                        request_sent_at = Instant::now();
                    }
                    NetworkEvent::RPCFailed {
                        app_request_id: _,
                        peer_id: _,
                        error,
                    } => {
                        error!(?error, "RPC Failed");
                        panic!("Rpc failed.");
                    }
                    _ => {}
                }
            }
        };

        // build the receiver future
        let receiver_future = async {
            loop {
                if let NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } = receiver.next_event().await
                {
                    assert_eq!(request_type, rpc_request);
                    debug!("Receiver received request");
                    receiver.send_response(peer_id, inbound_request_id, rpc_response.clone());
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

// Test that a rate-limited error doesn't occur even if the sender attempts to send many requests at
// once, thanks to the self-limiter on the sender side.
#[test]
fn test_active_requests() {
    // Set up the logging.
    let _subscriber = build_tracing_subscriber("debug", true);
    let rt = Arc::new(Runtime::new().unwrap());
    let spec = Arc::new(spec_with_all_forks_enabled());

    rt.block_on(async {
        // Get sender/receiver.
        let (mut sender, mut receiver) = common::build_node_pair(
            Arc::downgrade(&rt),
            ForkName::Base,
            spec,
            Protocol::Tcp,
            false,
            None,
        )
        .await;

        // Dummy STATUS RPC request.
        let rpc_request = RequestType::Status(StatusMessage::V2(StatusMessageV2 {
            fork_digest: [0; 4],
            finalized_root: Hash256::from_low_u64_be(0),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::from_low_u64_be(0),
            head_slot: Slot::new(1),
            earliest_available_slot: Slot::new(0),
        }));

        // Dummy STATUS RPC response.
        let rpc_response = Response::Status(StatusMessage::V2(StatusMessageV2 {
            fork_digest: [0; 4],
            finalized_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::zero(),
            head_slot: Slot::new(1),
            earliest_available_slot: Slot::new(0),
        }));

        // Number of requests.
        const REQUESTS: u8 = 10;

        // Build the sender future.
        let sender_future = async {
            let mut response_received = 0;
            loop {
                match sender.next_event().await {
                    NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                        debug!("Sending RPC request");
                        // Send requests in quick succession to intentionally trigger request queueing in the self-limiter.
                        for _ in 0..REQUESTS {
                            sender
                                .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                                .unwrap();
                        }
                    }
                    NetworkEvent::ResponseReceived { response, .. } => {
                        debug!(?response, "Sender received response");
                        if matches!(response, Response::Status(_)) {
                            response_received += 1;
                        }
                    }
                    NetworkEvent::RPCFailed {
                        app_request_id: _,
                        peer_id: _,
                        error,
                    } => panic!("RPC failed: {:?}", error),
                    _ => {}
                }

                if response_received == REQUESTS {
                    return;
                }
            }
        };

        // Build the receiver future.
        let receiver_future = async {
            let mut received_requests = vec![];
            loop {
                tokio::select! {
                    event = receiver.next_event() => {
                       if let NetworkEvent::RequestReceived { peer_id, inbound_request_id, request_type } = event {
                            debug!(?request_type, "Receiver received request");
                            if matches!(request_type, RequestType::Status(_)) {
                                received_requests.push((peer_id, inbound_request_id));
                            }
                        }
                    }
                    // Introduce a delay in sending responses to trigger request queueing on the sender side.
                    _ = sleep(Duration::from_secs(3)) => {
                        for (peer_id, inbound_request_id) in received_requests.drain(..) {
                            receiver.send_response(peer_id, inbound_request_id, rpc_response.clone());
                        }
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
