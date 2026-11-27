//! Complete aggregate payload-copy accounting. All observer callbacks and timer drains run on
//! the owning network task. No traffic is inferred from publication recipient estimates.

use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use libp2p::gossipsub::{PayloadDirection, TopicHash};
use pq_measurement::traffic::{Collector, CopyBasis, Direction, Encoding, Limits, Scope, Topic};
use std::sync::Arc;
use std::time::Duration;
use types::{ChainSpec, ForkContext, ForkName};

pub(super) struct PqTraffic {
    collector: Arc<Collector>,
    interval: tokio::time::Interval,
}

impl PqTraffic {
    pub(super) fn new(spec: &ChainSpec, forks: &ForkContext) -> Result<Option<Self>, String> {
        let Some(recorder) = pq_measurement::global() else {
            return Ok(None);
        };
        // Include configured PQ digests, never arbitrary topics supplied by a remote peer.
        let names = configured_topics(spec, forks);
        if names.is_empty() {
            return Ok(None);
        }
        let topics = names
            .into_iter()
            .map(|name| Topic {
                name,
                rx_scope: Scope {
                    code_location: "gossipsub::Behaviour::on_connection_handler_event Message entry, both decoded lists before filtering".into(),
                    payload_encoding: Encoding::Compressed,
                    copy_basis: CopyBasis::AllReceivedCopies,
                },
                tx_scope: Scope {
                    code_location: "gossipsub::Behaviour::send_message after peer.messages.try_push succeeds".into(),
                    payload_encoding: Encoding::Compressed,
                    copy_basis: CopyBasis::PerRecipient,
                },
            })
            .collect();
        let collector = Collector::new(recorder.clone(), topics, Limits::default())?;
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Ok(Some(Self {
            collector,
            interval,
        }))
    }

    pub(super) fn observer(
        &self,
    ) -> impl Fn(PayloadDirection, &TopicHash, usize) + Send + Sync + 'static {
        let collector = self.collector.clone();
        move |direction, topic, bytes| {
            collector.observe(
                match direction {
                    PayloadDirection::Inbound => Direction::Rx,
                    PayloadDirection::Outbound => Direction::Tx,
                },
                topic.as_str(),
                bytes,
            );
        }
    }

    pub(super) fn flush(&self) {
        self.collector.tick();
    }
}

fn configured_topics(spec: &ChainSpec, forks: &ForkContext) -> Vec<String> {
    let mut names = spec
        .all_digest_epochs()
        .filter(|epoch| spec.fork_name_at_epoch(*epoch) == ForkName::Pq)
        .map(|epoch| {
            GossipTopic::new(
                GossipKind::BeaconAggregateAndProof,
                GossipEncoding::default(),
                forks.context_bytes(epoch),
            )
            .to_string()
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names
}

impl Drop for PqTraffic {
    fn drop(&mut self) {
        // Queue only windows whose nominal close has passed. Partial shutdown windows stay unknown.
        self.collector.shutdown();
    }
}

pub(super) async fn wait_tick(traffic: &mut Option<PqTraffic>) {
    match traffic {
        Some(traffic) => {
            traffic.interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Epoch, Hash256, MainnetEthSpec, Slot};

    #[test]
    fn aggregate_traffic_allowlist_uses_configured_pq_digest_only() {
        let mut spec = ChainSpec::mainnet();
        let forks = ForkContext::new::<MainnetEthSpec>(Slot::new(0), Hash256::ZERO, &spec);
        assert!(configured_topics(&spec, &forks).is_empty());
        spec.pq_fork_epoch = Some(Epoch::new(0));
        let forks = ForkContext::new::<MainnetEthSpec>(Slot::new(0), Hash256::ZERO, &spec);
        let topics = configured_topics(&spec, &forks);
        assert!(!topics.is_empty());
        assert!(topics.iter().all(|topic| {
            topic.contains("/beacon_aggregate_and_proof/") && topic.ends_with("/ssz_snappy")
        }));
        let mut unique = topics.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique, topics);
        // A different genesis root has a different valid topic set: arbitrary remote topics
        // cannot extend this allowlist or allocate measurement state.
        let other =
            ForkContext::new::<MainnetEthSpec>(Slot::new(0), Hash256::repeat_byte(1), &spec);
        assert!(
            topics
                .iter()
                .all(|topic| !configured_topics(&spec, &other).contains(topic))
        );
    }
}
