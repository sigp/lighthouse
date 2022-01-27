use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::TopicHash;

use tokio_util::time::delay_queue::{DelayQueue, Key};
use types::{ChainSpec, EthSpec};

pub struct GossipCache {
    /// Expire timeouts for each topic-msg pair.
    expirations: DelayQueue<(TopicHash, Vec<u8>)>,
    /// Messages cached for each topic.
    topic_msgs: HashMap<TopicHash, HashMap<Vec<u8>, Key>>,
    /// Timeout to use when inserting new messages or updating existing ones.
    expire_timeout: Duration,
}

impl GossipCache {
    pub fn new<T: EthSpec>(spec: &ChainSpec) -> Self {
        GossipCache {
            expirations: DelayQueue::default(),
            topic_msgs: HashMap::default(),
            expire_timeout: Duration::from_secs(spec.seconds_per_slot * T::slots_per_epoch() / 2),
        }
    }

    // Insert a message to be sent later.
    pub fn insert(&mut self, topic: TopicHash, data: Vec<u8>) {
        match self
            .topic_msgs
            .entry(topic.clone())
            .or_default()
            .entry(data.clone())
        {
            Entry::Occupied(key) => self.expirations.reset(key.get(), self.expire_timeout),
            Entry::Vacant(entry) => {
                let key = self.expirations.insert((topic, data), self.expire_timeout);
                entry.insert(key);
            }
        }
    }

    // Get the registered messages for this topic.
    pub fn retrieve(&mut self, topic: &TopicHash) -> Option<impl Iterator<Item = Vec<u8>> + '_> {
        if let Some(msgs) = self.topic_msgs.remove(topic) {
            for (_, key) in msgs.iter() {
                self.expirations.remove(key);
            }
            Some(msgs.into_keys())
        } else {
            None
        }
    }
}

impl futures::stream::Stream for GossipCache {
    type Item = Result<(), String>; // We don't care to retrieve the expired data.

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.expirations.poll_expired(cx) {
            Poll::Ready(Some(Ok(expired))) => {
                let expected_key = expired.key();
                let (topic, data) = expired.into_inner();
                match self.topic_msgs.get_mut(&topic) {
                    Some(msgs) => {
                        let key = msgs.remove(&data);
                        debug_assert_eq!(key, Some(expected_key));
                        if msgs.is_empty() {
                            // no more messages for this topic.
                            self.topic_msgs.remove(&topic);
                        }
                    }
                    None => {
                        #[cfg(debug_assertions)]
                        panic!("Topic for registered message is not present.")
                    }
                }
                Poll::Ready(Some(Ok(())))
            }
            Poll::Ready(Some(Err(x))) => Poll::Ready(Some(Err(x.to_string()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::StreamExt;

    #[tokio::test]
    async fn test_stream() {
        let mut cache = GossipCache {
            expirations: DelayQueue::default(),
            topic_msgs: HashMap::default(),
            expire_timeout: Duration::from_millis(300),
        };
        let test_topic = TopicHash::from_raw("test");
        cache.insert(test_topic, vec![]);
        tokio::time::sleep(Duration::from_millis(300)).await;
        while cache.next().await.is_some() {}
    }
}
