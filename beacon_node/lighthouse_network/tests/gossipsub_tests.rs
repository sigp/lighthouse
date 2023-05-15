#![cfg(test)]
/// Gossipsub tests
///
/// Note: The aim of these tests is not to test the robustness of the gossip network
/// but to check if the gossipsub implementation is behaving according to the specifications.

/// Test if gossipsub message are forwarded by nodes with a simple linear topology.
///
///                Topology used in test
///
/// node1 <-> node2 <-> node3 ..... <-> node(n-1) <-> node(n)
use std::sync::Arc;

use crate::types::GossipEncoding;
use ::types::{BeaconBlock, EthSpec, ForkName, MinimalEthSpec, Signature, SignedBeaconBlock};
use lighthouse_network::*;
use slog::{debug, Level};
use tokio::runtime::Runtime;

type E = MinimalEthSpec;

mod common;

/// The fork to use for this test module
const FORK: ForkName = ForkName::Capella;

#[tokio::test]
async fn test_gossipsub_forward() {
    // set up the logging. The level and enabled or not
    let log = common::build_log(Level::Info, false);

    let pubsub_message = PubsubMessage::BeaconBlock(Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::empty(&E::default_spec()),
        Signature::empty(),
    )));
    let publishing_topic: String = pubsub_message
        .topics(GossipEncoding::default(), [0, 0, 0, 0])
        .first()
        .unwrap()
        .clone()
        .into();

    /* build our nodes -- in a linear network topology */
    let runtime: Arc<Runtime> = Arc::new(Runtime::new().unwrap());
    let num_nodes = 20;
    let mut nodes: Vec<common::Libp2pInstance> =
        common::build_linear(Arc::downgrade(&runtime), log.clone(), num_nodes, FORK).await;

    /* counters for our main loop */
    let mut received_count = 0;
    let mut subscribed_count = 0;

    let fut = async move {
        for node in nodes.iter_mut() {
            loop {
                match node.next_event().await {
                    NetworkEvent::PubsubMessage {
                        topic,
                        message,
                        source: _,
                        id: _,
                    } => {
                        // Assert topic is the published topic
                        assert_eq!(topic, TopicHash::from_raw(publishing_topic.clone()));
                        // Assert message received is the correct one
                        assert_eq!(message, pubsub_message.clone());
                        received_count += 1;
                        node.publish(vec![message]);
                        // Test should succeed if all nodes except the publisher receive the message
                        if received_count == num_nodes - 1 {
                            debug!(log.clone(), "Received message at {} nodes", num_nodes - 1);
                            return;
                        }
                    }
                    //                    BehaviourEvent::PeerSubscribed(_, topic) => {
                    //                        // Publish on beacon block topic
                    //                        if topic == TopicHash::from_raw(publishing_topic.clone()) {
                    //                            subscribed_count += 1;
                    //                            // Every node except the corner nodes are connected to 2 nodes.
                    //                            if subscribed_count == (num_nodes * 2) - 2 {
                    //                                node.swarm.publish(vec![pubsub_message.clone()]);
                    //                            }
                    //                        }
                    //                    }
                    _ => break,
                }
            }
        }
    };

    tokio::select! {
        _ = fut => {}
        _ = tokio::time::sleep(tokio::time::Duration::from_millis(800)) => {
            panic!("Future timed out");
        }
    }
}

// Test publishing of a message with a full mesh for the topic
// Not very useful but this is the bare minimum functionality.
#[tokio::test]
async fn test_gossipsub_full_mesh_publish() {
    // set up the logging. The level and enabled or not
    let log = common::build_log(Level::Info, false);

    let pubsub_message = PubsubMessage::BeaconBlock(Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::empty(&E::default_spec()),
        Signature::empty(),
    )));
    let publishing_topic: String = pubsub_message
        .topics(GossipEncoding::default(), [0, 0, 0, 0])
        .first()
        .unwrap()
        .clone()
        .into();

    /* build our nodes -- in a mesh network topology */
    let runtime: Arc<Runtime> = Arc::new(Runtime::new().unwrap());
    let num_nodes = 20;
    let mut nodes: Vec<common::Libp2pInstance> =
        common::build_full_mesh(Arc::downgrade(&runtime), log.clone(), num_nodes, FORK).await;

    /* counters for our main loop */
    let mut received_count = 0;
    let mut subscribed_count = 0;

    let fut = async move {
        for node in nodes.iter_mut() {
            while let NetworkEvent::PubsubMessage { topic, message, .. } = node.next_event().await {
                // Assert topic is the published topic
                assert_eq!(topic, TopicHash::from_raw(publishing_topic.clone()));
                // Assert message received is the correct one
                assert_eq!(message, pubsub_message.clone());
                received_count += 1;
                if received_count == num_nodes - 1 {
                    return;
                }
            }
        }
        //        while let NetworkEvent::PeerSubscribed(_, topic) =
        //            publishing_node.next_event().await
        //        {
        //            // Publish on beacon block topic
        //            if topic == TopicHash::from_raw(publishing_topic.clone()) {
        //                subscribed_count += 1;
        //                if subscribed_count == num_nodes - 1 {
        //                    publishing_node.swarm.publish(vec![pubsub_message.clone()]);
        //                }
        //            }
        //        }
    };
    tokio::select! {
            _ = fut => {}
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(800)) => {
                panic!("Future timed out");
            }
    }
}
