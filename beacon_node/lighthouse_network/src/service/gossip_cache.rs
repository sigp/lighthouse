use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::types::GossipKind;
use crate::GossipTopic;

use tokio_util::time::delay_queue::{DelayQueue, Key};

/// Store of gossip messages that we failed to publish and will try again later. By default, all
/// messages are ignored. This behaviour can be changed using `GossipCacheBuilder::default_timeout`
/// to apply the same delay to every kind. Individual timeouts for specific kinds can be set and
/// will overwrite the default_timeout if present.
pub struct GossipCache {
    /// Expire timeouts for each topic-msg pair.
    expirations: DelayQueue<(GossipTopic, Vec<u8>)>,
    /// Messages cached for each topic.
    topic_msgs: HashMap<GossipTopic, HashMap<Vec<u8>, Key>>,
    /// Timeout for blocks.
    beacon_block: Option<Duration>,
    /// Timeout for aggregate attestations.
    aggregates: Option<Duration>,
    /// Timeout for attestations.
    attestation: Option<Duration>,
    /// Timeout for voluntary exits.
    voluntary_exit: Option<Duration>,
    /// Timeout for proposer slashings.
    proposer_slashing: Option<Duration>,
    /// Timeout for attester slashings.
    attester_slashing: Option<Duration>,
    /// Timeout for aggregated sync committee signatures.
    signed_contribution_and_proof: Option<Duration>,
    /// Timeout for sync committee messages.
    sync_committee_message: Option<Duration>,
}

#[derive(Default)]
pub struct GossipCacheBuilder {
    default_timeout: Option<Duration>,
    /// Timeout for blocks.
    beacon_block: Option<Duration>,
    /// Timeout for aggregate attestations.
    aggregates: Option<Duration>,
    /// Timeout for attestations.
    attestation: Option<Duration>,
    /// Timeout for voluntary exits.
    voluntary_exit: Option<Duration>,
    /// Timeout for proposer slashings.
    proposer_slashing: Option<Duration>,
    /// Timeout for attester slashings.
    attester_slashing: Option<Duration>,
    /// Timeout for aggregated sync committee signatures.
    signed_contribution_and_proof: Option<Duration>,
    /// Timeout for sync committee messages.
    sync_committee_message: Option<Duration>,
}

#[allow(dead_code)]
impl GossipCacheBuilder {
    /// By default, all timeouts all disabled. Setting a default timeout will enable all timeout
    /// that are not already set.
    pub fn default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = Some(timeout);
        self
    }
    /// Timeout for blocks.
    pub fn beacon_block_timeout(mut self, timeout: Duration) -> Self {
        self.beacon_block = Some(timeout);
        self
    }

    /// Timeout for aggregate attestations.
    pub fn aggregates_timeout(mut self, timeout: Duration) -> Self {
        self.aggregates = Some(timeout);
        self
    }

    /// Timeout for attestations.
    pub fn attestation_timeout(mut self, timeout: Duration) -> Self {
        self.attestation = Some(timeout);
        self
    }

    /// Timeout for voluntary exits.
    pub fn voluntary_exit_timeout(mut self, timeout: Duration) -> Self {
        self.voluntary_exit = Some(timeout);
        self
    }

    /// Timeout for proposer slashings.
    pub fn proposer_slashing_timeout(mut self, timeout: Duration) -> Self {
        self.proposer_slashing = Some(timeout);
        self
    }

    /// Timeout for attester slashings.
    pub fn attester_slashing_timeout(mut self, timeout: Duration) -> Self {
        self.attester_slashing = Some(timeout);
        self
    }

    /// Timeout for aggregated sync committee signatures.
    pub fn signed_contribution_and_proof_timeout(mut self, timeout: Duration) -> Self {
        self.signed_contribution_and_proof = Some(timeout);
        self
    }

    /// Timeout for sync committee messages.
    pub fn sync_committee_message_timeout(mut self, timeout: Duration) -> Self {
        self.sync_committee_message = Some(timeout);
        self
    }

    pub fn build(self) -> GossipCache {
        let GossipCacheBuilder {
            default_timeout,
            beacon_block,
            aggregates,
            attestation,
            voluntary_exit,
            proposer_slashing,
            attester_slashing,
            signed_contribution_and_proof,
            sync_committee_message,
        } = self;
        GossipCache {
            expirations: DelayQueue::default(),
            topic_msgs: HashMap::default(),
            beacon_block: beacon_block.or(default_timeout),
            aggregates: aggregates.or(default_timeout),
            attestation: attestation.or(default_timeout),
            voluntary_exit: voluntary_exit.or(default_timeout),
            proposer_slashing: proposer_slashing.or(default_timeout),
            attester_slashing: attester_slashing.or(default_timeout),
            signed_contribution_and_proof: signed_contribution_and_proof.or(default_timeout),
            sync_committee_message: sync_committee_message.or(default_timeout),
        }
    }
}

impl GossipCache {
    /// Get a builder of a `GossipCache`. Topic kinds for which no timeout is defined will be
    /// ignored if added in `insert`.
    pub fn builder() -> GossipCacheBuilder {
        GossipCacheBuilder::default()
    }

    // Insert a message to be sent later.
    pub fn insert(&mut self, topic: GossipTopic, data: Vec<u8>) {
        let expire_timeout = match topic.kind() {
            GossipKind::BeaconBlock => self.beacon_block,
            GossipKind::BeaconAggregateAndProof => self.aggregates,
            GossipKind::Attestation(_) => self.attestation,
            GossipKind::VoluntaryExit => self.voluntary_exit,
            GossipKind::ProposerSlashing => self.proposer_slashing,
            GossipKind::AttesterSlashing => self.attester_slashing,
            GossipKind::SignedContributionAndProof => self.signed_contribution_and_proof,
            GossipKind::SyncCommitteeMessage(_) => self.sync_committee_message,
        };
        let expire_timeout = match expire_timeout {
            Some(expire_timeout) => expire_timeout,
            None => return,
        };
        match self
            .topic_msgs
            .entry(topic.clone())
            .or_default()
            .entry(data.clone())
        {
            Entry::Occupied(key) => self.expirations.reset(key.get(), expire_timeout),
            Entry::Vacant(entry) => {
                let key = self.expirations.insert((topic, data), expire_timeout);
                entry.insert(key);
            }
        }
    }

    // Get the registered messages for this topic.
    pub fn retrieve(&mut self, topic: &GossipTopic) -> Option<impl Iterator<Item = Vec<u8>> + '_> {
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
    type Item = Result<GossipTopic, String>; // We don't care to retrieve the expired data.

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
                Poll::Ready(Some(Ok(topic)))
            }
            Poll::Ready(Some(Err(x))) => Poll::Ready(Some(Err(x.to_string()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::GossipKind;

    use super::*;
    use futures::stream::StreamExt;

    #[tokio::test]
    async fn test_stream() {
        let mut cache = GossipCache::builder()
            .default_timeout(Duration::from_millis(300))
            .build();
        let test_topic = GossipTopic::new(
            GossipKind::Attestation(1u64.into()),
            crate::types::GossipEncoding::SSZSnappy,
            [0u8; 4],
        );
        cache.insert(test_topic, vec![]);
        tokio::time::sleep(Duration::from_millis(300)).await;
        while cache.next().await.is_some() {}
        assert!(cache.expirations.is_empty());
        assert!(cache.topic_msgs.is_empty());
    }
}
