//! A collection of gossipsub messages that can be sent simultaneously through the network channel.

use crate::{GossipTopic, PubsubMessage};
use types::EthSpec;

#[derive(Debug)]
pub struct GossipMessage<T: EthSpec> {
    /// A list of topics that the message will be sent on.
    topics: Vec<GossipTopic>,
    /// The message to be sent on the provided topics.
    message: PubsubMessage<T>,
}

impl<T: EthSpec> GossipMessage<T> {
    /// Creates a new `GossipMessage`. Fails if no topic is supplied.
    pub fn new(topics: Vec<GossipTopic>, message: PubsubMessage<T>) -> Result<Self, &'static str> {
        if topics.is_empty() {
            return Err("Must supply a topic");
        }

        Ok(GossipMessage { topics, message })
    }

    /// Adds a topic to the message.
    pub fn add_topic(&mut self, topic: GossipTopic) {
        self.topics.push(topic);
    }

    /// Returns the topics associated with the `GossipMessage`.
    pub fn topics(&self) -> &[GossipTopic] {
        &self.topics
    }

    /// Gets a reference to the underlying message.
    pub fn get_message(&self) -> &PubsubMessage<T> {
        &self.message
    }

    /// Consumes self returning the underlying message.
    pub fn into_message(self) -> PubsubMessage<T> {
        self.message
    }

    /// Consumes self and returns a tuple containing the topics and underlying message.
    pub fn into_topic_message(self) -> (Vec<GossipTopic>, PubsubMessage<T>) {
        (self.topics, self.message)
    }
}
