use crate::BeaconNodeFallback;
use eth2::types::{EventKind, EventTopic, Hash256, SseHead};
use futures::StreamExt;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use types::EthSpec;

type CacheHashMap = HashMap<usize, SseHead>;

// This is used to send the index derived from `CandidateBeaconNode` to the
// `AttestationService` for further processing
#[derive(Debug)]
pub struct HeadEvent {
    pub beacon_node_index: usize,
    pub slot: types::Slot,
    pub beacon_block_root: Hash256,
}

/// Cache to maintain the latest head received from each of the beacon nodes
/// in the `BeaconNodeFallback`.
#[derive(Debug)]
pub struct BeaconHeadCache {
    cache: RwLock<CacheHashMap>,
}

impl BeaconHeadCache {
    /// Creates a new empty beacon head cache.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Retrieves the cached head for a specific beacon node.
    /// Returns `None` if no head has been cached for that node yet.
    pub async fn get(&self, beacon_node_index: usize) -> Option<SseHead> {
        self.cache.read().await.get(&beacon_node_index).cloned()
    }

    /// Stores or updates the head event for a specific beacon node.
    /// Replaces any previously cached head for the given node.
    pub async fn insert(&self, beacon_node_index: usize, head: SseHead) {
        self.cache.write().await.insert(beacon_node_index, head);
    }

    /// Checks if the given head is the latest among all cached heads.
    /// Returns `true` if the head's slot is >= all cached heads' slots.
    pub async fn is_latest(&self, head: &SseHead) -> bool {
        let cache = self.cache.read().await;
        cache
            .values()
            .all(|cache_head| head.slot >= cache_head.slot)
    }

    /// Clears all cached heads, removing entries for all beacon nodes.
    /// Useful when beacon node candidates are refreshed to avoid stale references.
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
// potential start attestation duties earlier as soon as latest head is receive from any of the
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
        .ok_or("Unable to start head monitor without beacon_head_cache")?;
    let head_monitor_send = beacon_nodes
        .head_monitor_send
        .clone()
        .ok_or("Unable to start head monitor without head_monitor_send")?;

    info!("Starting head monitoring service");
    let candidates = {
        let candidates_guard = beacon_nodes.candidates.read().await;
        candidates_guard.clone()
    };

    // Clear the cache in case it contains stale data from a previous run. This function gets
    // restarted if it fails (see monitoring in `start_fallback_updater_service`).
    head_cache.purge_cache().await;

    // Create Vec of streams, which we will select over.
    let mut streams = vec![];

    for candidate in &candidates {
        let head_event_stream = candidate
            .beacon_node
            .get_events::<E>(&[EventTopic::Head])
            .await;

        let head_event_stream = match head_event_stream {
            Ok(stream) => stream,
            Err(e) => {
                warn!(error = ?e, node_index = candidate.index, "Failed to get head event stream");
                continue;
            }
        };

        streams.push(head_event_stream.map(|event| (candidate.index, event)));
    }

    if streams.is_empty() {
        return Err("No beacon nodes available for head event streaming".to_string());
    }

    // Combine streams into a single stream and poll events from any of them.
    let mut combined_stream = futures::stream::select_all(streams);

    while let Some((candidate_index, event_result)) = combined_stream.next().await {
        match event_result {
            Ok(EventKind::Head(head)) => {
                debug!(
                    candidate_index,
                    block_root = ?head.block,
                    slot = %head.slot,
                    "New head from beacon node"
                );

                // Skip optimistic heads - the beacon node can't produce valid
                // attestation data when its execution layer is not verified
                if head.execution_optimistic {
                    debug!(
                        candidate_index,
                        block_root = ?head.block,
                        slot = %head.slot,
                        "Skipping optimistic head"
                    );
                    continue;
                }

                head_cache.insert(candidate_index, head.clone()).await;

                if !head_cache.is_latest(&head).await {
                    debug!(
                        candidate_index,
                        block_root = ?head.block,
                        slot = %head.slot,
                        "Skipping stale head"
                    );
                    continue;
                }

                if head_monitor_send
                    .send(HeadEvent {
                        beacon_node_index: candidate_index,
                        slot: head.slot,
                        beacon_block_root: head.block,
                    })
                    .await
                    .is_err()
                {
                    return Err("Head monitoring service channel closed".into());
                }
            }
            Ok(event) => {
                warn!(
                    event_kind = event.topic_name(),
                    candidate_index, "Received unexpected event from BN"
                );
                continue;
            }
            Err(e) => {
                return Err(format!(
                    "Head monitoring stream error, node: {candidate_index}, error: {e:?}"
                ));
            }
        }
    }

    Err("Stream ended unexpectedly".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::FixedBytesExtended;
    use types::{Hash256, Slot};

    fn create_sse_head(slot: u64, block_root: u8) -> SseHead {
        SseHead {
            slot: types::Slot::new(slot),
            block: Hash256::from_low_u64_be(block_root as u64),
            state: Hash256::from_low_u64_be(block_root as u64),
            epoch_transition: false,
            previous_duty_dependent_root: Hash256::from_low_u64_be(block_root as u64),
            current_duty_dependent_root: Hash256::from_low_u64_be(block_root as u64),
            execution_optimistic: false,
        }
    }

    #[tokio::test]
    async fn test_beacon_head_cache_insertion_and_retrieval() {
        let cache = BeaconHeadCache::new();
        let head_1 = create_sse_head(1, 1);
        let head_2 = create_sse_head(2, 2);

        cache.insert(0, head_1.clone()).await;
        cache.insert(1, head_2.clone()).await;

        assert_eq!(cache.get(0).await, Some(head_1));
        assert_eq!(cache.get(1).await, Some(head_2));
        assert_eq!(cache.get(2).await, None);
    }

    #[tokio::test]
    async fn test_beacon_head_cache_update() {
        let cache = BeaconHeadCache::new();
        let head_old = create_sse_head(1, 1);
        let head_new = create_sse_head(2, 2);

        cache.insert(0, head_old).await;
        cache.insert(0, head_new.clone()).await;

        assert_eq!(cache.get(0).await, Some(head_new));
    }

    #[tokio::test]
    async fn test_is_latest_with_higher_slot() {
        let cache = BeaconHeadCache::new();
        let head_1 = create_sse_head(1, 1);
        let head_2 = create_sse_head(2, 2);
        let head_3 = create_sse_head(3, 3);

        cache.insert(0, head_1).await;
        cache.insert(1, head_2).await;

        assert!(cache.is_latest(&head_3).await);
    }

    #[tokio::test]
    async fn test_is_latest_with_lower_slot() {
        let cache = BeaconHeadCache::new();
        let head_1 = create_sse_head(1, 1);
        let head_2 = create_sse_head(2, 2);
        let head_older = create_sse_head(1, 99);

        cache.insert(0, head_1).await;
        cache.insert(1, head_2).await;

        assert!(!cache.is_latest(&head_older).await);
    }

    #[tokio::test]
    async fn test_is_latest_with_equal_slot() {
        let cache = BeaconHeadCache::new();
        let head_1 = create_sse_head(5, 1);
        let head_2 = create_sse_head(5, 2);
        let head_equal = create_sse_head(5, 3);

        cache.insert(0, head_1).await;
        cache.insert(1, head_2).await;

        assert!(cache.is_latest(&head_equal).await);
    }

    #[tokio::test]
    async fn test_is_latest_empty_cache() {
        let cache = BeaconHeadCache::new();
        let head = create_sse_head(1, 1);

        assert!(cache.is_latest(&head).await);
    }

    #[tokio::test]
    async fn test_purge_cache_clears_all_entries() {
        let cache = BeaconHeadCache::new();
        let head_1 = create_sse_head(1, 1);
        let head_2 = create_sse_head(2, 2);

        cache.insert(0, head_1).await;
        cache.insert(1, head_2).await;

        assert!(cache.get(0).await.is_some());
        assert!(cache.get(1).await.is_some());

        cache.purge_cache().await;

        assert!(cache.get(0).await.is_none());
        assert!(cache.get(1).await.is_none());
    }

    #[tokio::test]
    async fn test_head_event_creation() {
        let block_root = Hash256::from_low_u64_be(99);
        let event = HeadEvent {
            beacon_node_index: 42,
            slot: Slot::new(123),
            beacon_block_root: block_root,
        };
        assert_eq!(event.beacon_node_index, 42);
        assert_eq!(event.slot, Slot::new(123));
        assert_eq!(event.beacon_block_root, block_root);
    }

    #[tokio::test]
    async fn test_cache_caches_multiple_heads_from_different_nodes() {
        let cache = BeaconHeadCache::new();
        let head_1 = create_sse_head(10, 1);
        let head_2 = create_sse_head(5, 2);
        let head_3 = create_sse_head(8, 3);

        cache.insert(0, head_1.clone()).await;
        cache.insert(1, head_2.clone()).await;
        cache.insert(2, head_3.clone()).await;

        // Verify all are stored
        assert_eq!(cache.get(0).await, Some(head_1));
        assert_eq!(cache.get(1).await, Some(head_2));
        assert_eq!(cache.get(2).await, Some(head_3));

        // The latest should be slot 10
        let head_10 = create_sse_head(10, 99);
        assert!(cache.is_latest(&head_10).await);

        // Anything with slot > 10 should be latest
        let head_11 = create_sse_head(11, 99);
        assert!(cache.is_latest(&head_11).await);

        // Anything with slot < 10 should not be latest
        let head_9 = create_sse_head(9, 99);
        assert!(!cache.is_latest(&head_9).await);
    }

    #[tokio::test]
    async fn test_cache_handles_concurrent_operations() {
        let cache = Arc::new(BeaconHeadCache::new());
        let mut handles = vec![];

        // Spawn multiple tasks that insert heads concurrently
        for i in 0..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                let head = create_sse_head(i as u64, (i % 256) as u8);
                cache_clone.insert(i, head).await;
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all heads are cached
        for i in 0..10 {
            assert!(cache.get(i).await.is_some());
        }
    }

    #[tokio::test]
    async fn test_is_latest_after_cache_updates() {
        let cache = BeaconHeadCache::new();

        // Start with head at slot 5
        let head_5 = create_sse_head(5, 1);
        cache.insert(0, head_5.clone()).await;
        assert!(cache.is_latest(&head_5).await);

        // Add a higher slot
        let head_10 = create_sse_head(10, 2);
        cache.insert(1, head_10.clone()).await;

        // head_5 should no longer be latest
        assert!(!cache.is_latest(&head_5).await);
        // head_10 should be latest
        assert!(cache.is_latest(&head_10).await);

        // Add an even higher slot
        let head_15 = create_sse_head(15, 3);
        cache.insert(2, head_15.clone()).await;

        // head_10 should no longer be latest
        assert!(!cache.is_latest(&head_10).await);
        // head_15 should be latest
        assert!(cache.is_latest(&head_15).await);
    }

    #[tokio::test]
    async fn test_cache_default_is_empty() {
        let cache = BeaconHeadCache::default();
        assert!(cache.get(0).await.is_none());
        assert!(cache.get(999).await.is_none());
    }

    #[tokio::test]
    async fn test_is_latest_with_multiple_same_slot_heads() {
        let cache = BeaconHeadCache::new();
        let head_slot_5_node1 = create_sse_head(5, 1);
        let head_slot_5_node2 = create_sse_head(5, 2);
        let head_slot_5_node3 = create_sse_head(5, 3);

        cache.insert(0, head_slot_5_node1).await;
        cache.insert(1, head_slot_5_node2).await;

        // All heads with slot 5 should be considered latest
        assert!(cache.is_latest(&head_slot_5_node3).await);

        // But heads with slot 4 should not be latest
        let head_slot_4 = create_sse_head(4, 4);
        assert!(!cache.is_latest(&head_slot_4).await);
    }
}
