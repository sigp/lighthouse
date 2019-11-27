#![cfg(test)]
use eth2_libp2p::*;
use futures::prelude::*;
use slog::{debug, Level};

mod common;

/* Gossipsub tests */
// Note: The aim of these tests is not to test the robustness of the gossip network
// but to check if the gossipsub implementation is behaving according to the specifications.

// Test if gossipsub message are forwarded by nodes with a simple linear topology.
//
//                Topology used in test
//
// node1 <-> node2 <-> node3 ..... <-> node(n-1) <-> node(n)

#[test]
fn test_gossipsub_forward() {
    // set up the logging. The level and enabled or not
    let log = common::build_log(Level::Info, false);

    let num_nodes = 20;
    let mut nodes = common::build_linear(log.clone(), num_nodes, Some(19000));
    let mut received_count = 0;
    let pubsub_message = PubsubMessage::Block(vec![0; 4]);
    let publishing_topic: String = "/eth2/beacon_block/ssz".into();
    let mut subscribed_count = 0;
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for node in nodes.iter_mut() {
            loop {
                match node.poll().unwrap() {
                    Async::Ready(Some(Libp2pEvent::PubsubMessage {
                        topics,
                        message,
                        source,
                        id,
                    })) => {
                        assert_eq!(topics.len(), 1);
                        // Assert topic is the published topic
                        assert_eq!(
                            topics.first().unwrap(),
                            &TopicHash::from_raw(publishing_topic.clone())
                        );
                        // Assert message received is the correct one
                        assert_eq!(message, pubsub_message.clone());
                        received_count += 1;
                        // Since `propagate_message` is false, need to propagate manually
                        node.swarm.propagate_message(&source, id);
                        // Test should succeed if all nodes except the publisher receive the message
                        if received_count == num_nodes - 1 {
                            debug!(log.clone(), "Received message at {} nodes", num_nodes - 1);
                            return Ok(Async::Ready(()));
                        }
                    }
                    Async::Ready(Some(Libp2pEvent::PeerSubscribed(_, topic))) => {
                        // Received topics is one of subscribed eth2 topics
                        assert!(topic.clone().into_string().starts_with("/eth2/"));
                        // Publish on beacon block topic
                        if topic == TopicHash::from_raw("/eth2/beacon_block/ssz") {
                            subscribed_count += 1;
                            // Every node except the corner nodes are connected to 2 nodes.
                            if subscribed_count == (num_nodes * 2) - 2 {
                                node.swarm.publish(
                                    &vec![Topic::new(topic.into_string())],
                                    pubsub_message.clone(),
                                );
                            }
                        }
                    }
                    _ => break,
                }
            }
        }
        Ok(Async::NotReady)
    }))
}

// Test publishing of a message with a full mesh for the topic
// Not very useful but this is the bare minimum functionality.
#[test]
fn test_gossipsub_full_mesh_publish() {
    // set up the logging. The level and enabled or not
    let log = common::build_log(Level::Info, false);

    let num_nodes = 20;
    let mut nodes = common::build_full_mesh(log, num_nodes, None);
    let mut publishing_node = nodes.pop().unwrap();
    let pubsub_message = PubsubMessage::Block(vec![0; 4]);
    let publishing_topic: String = "/eth2/beacon_block/ssz".into();
    let mut subscribed_count = 0;
    let mut received_count = 0;
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for node in nodes.iter_mut() {
            loop {
                match node.poll().unwrap() {
                    Async::Ready(Some(Libp2pEvent::PubsubMessage {
                        topics, message, ..
                    })) => {
                        assert_eq!(topics.len(), 1);
                        // Assert topic is the published topic
                        assert_eq!(
                            topics.first().unwrap(),
                            &TopicHash::from_raw(publishing_topic.clone())
                        );
                        // Assert message received is the correct one
                        assert_eq!(message, pubsub_message.clone());
                        received_count += 1;
                        if received_count == num_nodes - 1 {
                            return Ok(Async::Ready(()));
                        }
                    }
                    _ => break,
                }
            }
        }
        loop {
            match publishing_node.poll().unwrap() {
                Async::Ready(Some(Libp2pEvent::PeerSubscribed(_, topic))) => {
                    // Received topics is one of subscribed eth2 topics
                    assert!(topic.clone().into_string().starts_with("/eth2/"));
                    // Publish on beacon block topic
                    if topic == TopicHash::from_raw("/eth2/beacon_block/ssz") {
                        subscribed_count += 1;
                        if subscribed_count == num_nodes - 1 {
                            publishing_node.swarm.publish(
                                &vec![Topic::new(topic.into_string())],
                                pubsub_message.clone(),
                            );
                        }
                    }
                }
                _ => break,
            }
        }
        Ok(Async::NotReady)
    }))
}
