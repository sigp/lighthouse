use crate::BeaconNodeFallback;
use std::collections::HashMap;
use tokio::sync::RwLock;

use types::EthSpec;

use eth2::types::{EventKind, EventTopic, SseHead};
use tracing::{info, warn};

use futures::StreamExt;
use slot_clock::SlotClock;
use std::sync::Arc;

type CacheHashMap = HashMap<usize, SseHead>;

// This is used send the index derived from `CandidateBeaconNode` to the
// `AttestationService` for further processing
#[derive(Debug)]
pub struct HeadEvent {
    pub beacon_node_index: usize,
}

/// Cache to maintain the latest head received from each of the beacon nodes
/// in the `BeaconNodeFallback`.
#[derive(Debug)]
pub struct BeaconHeadCache {
    cache: RwLock<CacheHashMap>,
}

impl BeaconHeadCache {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get(&self, beacon_node_index: usize) -> Option<SseHead> {
        self.cache.read().await.get(&beacon_node_index).cloned()
    }

    pub async fn insert(&self, beacon_node_index: usize, head: SseHead) {
        self.cache.write().await.insert(beacon_node_index, head);
    }

    pub async fn is_latest(&self, head: &SseHead) -> bool {
        let cache = self.cache.read().await;
        cache
            .values()
            .all(|cache_head| head.slot >= cache_head.slot)
    }

    pub async fn purge_cache(&self) {
        self.cache.write().await.clear();
    }
}

impl Default for BeaconHeadCache {
    fn default() -> Self {
        Self::new()
    }
}

// Runs a non-terminating loop to update the `BeaconHeadCache` with the latest head received
// from the candidate beacon_nodes. This is an attempt to stream events to beacon nodes and
// potential start attestion duties earlier as soon as latest head is receive from any of the
// beacon node in contrast to attest at the 1/3rd mark in the slot.
//
//
// The cache and the candidate BNs list are refresh/purged to avoid dangling reference conditions
// that arise due to `update_candidates_list`.
//
// Starts the service to perpetually stream head events from connected beacon_nodes
pub async fn poll_head_event_from_beacon_nodes<E: EthSpec, T: SlotClock + 'static>(
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
) -> Result<(), String> {
    let head_cache = beacon_nodes
        .beacon_head_cache
        .clone()
        .expect("Unable to start head monitor without beacon_head_cache");
    let head_monitor_send = beacon_nodes
        .head_monitor_send
        .clone()
        .expect("Unable to start head monitor without head_monitor_send");

    info!("Starting head monitoring service");
    let candidates = {
        let candidates_guard = beacon_nodes.candidates.read().await;
        candidates_guard.clone()
    };
    let mut tasks = vec![];

    for candidate in candidates.iter() {
        let head_event_stream = candidate
            .beacon_node
            .get_events::<E>(&[EventTopic::Head])
            .await;

        let mut head_event_stream = match head_event_stream {
            Ok(stream) => stream,
            Err(e) => {
                warn!("failed to get head event stream: {:?}", e);
                continue;
            }
        };

        let sender_tx = head_monitor_send.clone();
        let head_cache_ref = head_cache.clone();

        let stream_fut = async move {
            while let Some(event_result) = head_event_stream.next().await {
                if let Ok(EventKind::Head(head)) = event_result {
                    head_cache_ref.insert(candidate.index, head.clone()).await;

                    if !head_cache_ref.is_latest(&head).await {
                        continue;
                    }

                    if sender_tx
                        .send(HeadEvent {
                            beacon_node_index: candidate.index,
                        })
                        .await
                        .is_err()
                    {
                        warn!("Head monitoring service channel closed");
                    }
                }
            }
        };

        tasks.push(stream_fut);
    }

    if tasks.is_empty() {
        head_cache.purge_cache().await;
        return Err(
            "No beacon nodes available for head event streaming, retry in sometime".to_string(),
        );
    }

    futures::future::join_all(tasks).await;

    drop(candidates);
    head_cache.purge_cache().await;

    Ok(())
}
