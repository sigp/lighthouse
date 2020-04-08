#![cfg(test)]
use crate::types::GossipEncoding;
use ::types::{BeaconBlock, EthSpec, MinimalEthSpec, Signature, SignedBeaconBlock};
use eth2_libp2p::*;
use futures::prelude::*;
use slog::{debug, Level};

type E = MinimalEthSpec;

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
    let spec = E::default_spec();
    let empty_block = BeaconBlock::empty(&spec);
    let signed_block = SignedBeaconBlock {
        message: empty_block,
        signature: Signature::empty_signature(),
    };
    let pubsub_message = PubsubMessage::BeaconBlock(Box::new(signed_block));
    let publishing_topic: String = pubsub_message
        .topics(GossipEncoding::default(), [0, 0, 0, 0])
        .first()
        .unwrap()
        .clone()
        .into();
    let mut subscribed_count = 0;
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for node in nodes.iter_mut() {
            loop {
                match node.poll().unwrap() {
                    Async::Ready(Some(BehaviourEvent::PubsubMessage {
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
                    Async::Ready(Some(BehaviourEvent::PeerSubscribed(_, topic))) => {
                        // Publish on beacon block topic
                        if topic == TopicHash::from_raw(publishing_topic.clone()) {
                            subscribed_count += 1;
                            // Every node except the corner nodes are connected to 2 nodes.
                            if subscribed_count == (num_nodes * 2) - 2 {
                                node.swarm.publish(vec![pubsub_message.clone()]);
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
    let log = common::build_log(Level::Debug, false);

    // Note: This test does not propagate gossipsub messages.
    // Having `num_nodes` > `mesh_n_high` may give inconsistent results
    // as nodes may get pruned out of the mesh before the gossipsub message
    // is published to them.
    let num_nodes = 12;
    let mut nodes = common::build_full_mesh(log, num_nodes, Some(11320));
    let mut publishing_node = nodes.pop().unwrap();
    let spec = E::default_spec();
    let empty_block = BeaconBlock::empty(&spec);
    let signed_block = SignedBeaconBlock {
        message: empty_block,
        signature: Signature::empty_signature(),
    };
    let pubsub_message = PubsubMessage::BeaconBlock(Box::new(signed_block));
    let publishing_topic: String = pubsub_message
        .topics(GossipEncoding::default(), [0, 0, 0, 0])
        .first()
        .unwrap()
        .clone()
        .into();
    let mut subscribed_count = 0;
    let mut received_count = 0;
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for node in nodes.iter_mut() {
            while let Async::Ready(Some(BehaviourEvent::PubsubMessage {
                topics, message, ..
            })) = node.poll().unwrap()
            {
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
        }
        while let Async::Ready(Some(BehaviourEvent::PeerSubscribed(_, topic))) =
            publishing_node.poll().unwrap()
        {
            // Publish on beacon block topic
            if topic == TopicHash::from_raw(publishing_topic.clone()) {
                subscribed_count += 1;
                if subscribed_count == num_nodes - 1 {
                    publishing_node.swarm.publish(vec![pubsub_message.clone()]);
                }
            }
        }
        Ok(Async::NotReady)
    }))
}
