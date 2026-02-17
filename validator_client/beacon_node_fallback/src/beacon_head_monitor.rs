use crate::{BeaconNodeFallback, CandidateBeaconNode};
use eth2::types::{EventKind, EventTopic, Hash256, SseHead};
use futures::StreamExt;
use futures::stream::BoxStream;
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
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

enum StreamEvent<E: EthSpec> {
    Event(usize, Box<Result<EventKind<E>, eth2::Error>>),
    StreamEnded(usize),
}

/// Attempt to establish a head event stream for a single candidate beacon node.
/// Returns a boxed stream that yields `StreamEvent`s tagged with the candidate index,
/// followed by a `StreamEnded` sentinel when the SSE connection terminates.
/// Returns `None` if the initial connection fails.
async fn create_candidate_stream<E: EthSpec>(
    candidate: &CandidateBeaconNode,
) -> Option<BoxStream<'static, StreamEvent<E>>> {
    let idx = candidate.index;
    match candidate
        .beacon_node
        .get_events::<E>(&[EventTopic::Head])
        .await
    {
        Ok(stream) => {
            let wrapped = stream
                .map(move |event| StreamEvent::Event(idx, Box::new(event)))
                .chain(futures::stream::once(async move {
                    StreamEvent::StreamEnded(idx)
                }));
            Some(wrapped.boxed())
        }
        Err(e) => {
            warn!(error = ?e, node_index = idx, "Failed to establish head event stream");
            None
        }
    }
}

/// Streams head events from all candidate beacon nodes with per-stream resilience.
///
/// Unlike the previous implementation, a single stream error or disconnection does not
/// tear down all streams. Failed streams are retried periodically (once per slot).
/// Returns `Ok(())` when the candidate list is updated (signalled via `Notify`),
/// allowing the outer loop to restart with fresh candidates.
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

    // Create restart future FIRST — must exist before any notify_one() calls so
    // notifications aren't lost per tokio::sync::Notify semantics.
    let restart_notify = beacon_nodes.head_monitor_restart_notify().cloned();
    let restart_fut = async {
        match &restart_notify {
            Some(notify) => notify.notified().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(restart_fut);

    info!("Starting head monitoring service");
    let candidates = beacon_nodes.candidates.read().await.clone();

    // Clear the cache in case it contains stale data from a previous run.
    head_cache.purge_cache().await;

    // Build initial streams
    let mut combined_stream = futures::stream::SelectAll::new();
    let mut failed_indices: HashSet<usize> = HashSet::new();

    for candidate in &candidates {
        match create_candidate_stream::<E>(candidate).await {
            Some(stream) => combined_stream.push(stream),
            None => {
                failed_indices.insert(candidate.index);
            }
        }
    }

    // Retry timer and failure tracking
    let slot_duration = beacon_nodes.spec.get_slot_duration();
    let mut retry_timer = tokio::time::interval(slot_duration);
    retry_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retry_timer.tick().await; // skip first immediate tick

    let mut consecutive_all_failed: usize = 0;
    const MAX_CONSECUTIVE_ALL_FAILED: usize = 5;

    loop {
        tokio::select! {
            maybe_event = combined_stream.next() => {
                match maybe_event {
                    Some(StreamEvent::Event(candidate_index, result)) => {
                        match *result {
                            Ok(EventKind::Head(head)) => {
                                debug!(
                                    candidate_index,
                                    block_root = ?head.block,
                                    slot = %head.slot,
                                    "New head from beacon node"
                                );

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

                                consecutive_all_failed = 0;
                            }
                            Ok(event) => {
                                warn!(event_kind = event.topic_name(), "Unexpected event from BN");
                            }
                            Err(e) => {
                                warn!(error = ?e, node_index = candidate_index, "Head event stream error");
                            }
                        }
                    }
                    Some(StreamEvent::StreamEnded(idx)) => {
                        warn!(node_index = idx, "Head event stream ended, will retry");
                        failed_indices.insert(idx);
                    }
                    None => {
                        // SelectAll is empty — all streams have terminated.
                        if failed_indices.is_empty() {
                            return Err("All head event streams ended".into());
                        }
                    }
                }
            }

            // Retry failed streams periodically
            _ = retry_timer.tick() => {
                if failed_indices.is_empty() {
                    continue;
                }

                let candidates = beacon_nodes.candidates.read().await.clone();
                let mut reconnected = Vec::new();

                for &idx in &failed_indices {
                    if let Some(candidate) = candidates.iter().find(|c| c.index == idx)
                        && let Some(stream) = create_candidate_stream::<E>(candidate).await
                    {
                        info!(node_index = idx, "Reconnected head event stream");
                        combined_stream.push(stream);
                        reconnected.push(idx);
                    }
                    // If candidate no longer in list, drop silently
                }

                for idx in reconnected {
                    failed_indices.remove(&idx);
                }

                if combined_stream.is_empty() && !failed_indices.is_empty() {
                    consecutive_all_failed += 1;
                    if consecutive_all_failed >= MAX_CONSECUTIVE_ALL_FAILED {
                        return Err(format!(
                            "All beacon nodes unreachable for {} consecutive retries",
                            consecutive_all_failed
                        ));
                    }
                } else {
                    consecutive_all_failed = 0;
                }
            }

            // Restart signal from candidate list update
            _ = &mut restart_fut => {
                info!("Candidate list updated, restarting head monitor");
                head_cache.purge_cache().await;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::FixedBytesExtended;
    use types::{Hash256, MainnetEthSpec, Slot};

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

    type E = MainnetEthSpec;

    /// Create a boxed stream from a futures mpsc channel, tagged with a candidate index.
    /// The stream yields `StreamEvent::Event` for each item and `StreamEvent::StreamEnded`
    /// when the channel is closed.
    fn channel_to_stream(
        idx: usize,
        rx: futures::channel::mpsc::Receiver<Result<eth2::types::EventKind<E>, eth2::Error>>,
    ) -> futures::stream::BoxStream<'static, StreamEvent<E>> {
        rx.map(move |event| StreamEvent::Event(idx, Box::new(event)))
            .chain(futures::stream::once(async move {
                StreamEvent::StreamEnded(idx)
            }))
            .boxed()
    }

    /// Tests that when one stream in a SelectAll disconnects (channel drops),
    /// events from the remaining streams continue to be received.
    #[tokio::test]
    async fn test_stream_disconnect_does_not_affect_other_streams() {
        let (mut tx0, rx0) = futures::channel::mpsc::channel(16);
        let (mut tx1, rx1) = futures::channel::mpsc::channel(16);

        let mut combined = futures::stream::SelectAll::new();
        combined.push(channel_to_stream(0, rx0));
        combined.push(channel_to_stream(1, rx1));

        let head = create_sse_head(1, 1);
        let event = eth2::types::EventKind::<E>::Head(head.clone());

        // Send an event from stream 0
        tx0.try_send(Ok(event)).unwrap();

        // Drop stream 0's sender to simulate disconnection
        drop(tx0);

        // Collect events: should get the Event from idx=0, then StreamEnded(0)
        let mut got_event = false;

        // Drain events from the disconnected stream
        loop {
            let item = combined.next().await.unwrap();
            match item {
                StreamEvent::Event(0, result)
                    if matches!(&*result, Ok(eth2::types::EventKind::Head(_))) =>
                {
                    got_event = true;
                }
                StreamEvent::StreamEnded(0) => break,
                _ => {}
            }
        }
        assert!(
            got_event,
            "Should have received the head event from stream 0"
        );

        // Stream 1 should still work
        let head2 = create_sse_head(2, 2);
        let event2 = eth2::types::EventKind::<E>::Head(head2.clone());
        tx1.try_send(Ok(event2)).unwrap();

        match combined.next().await.unwrap() {
            StreamEvent::Event(1, result) => match *result {
                Ok(eth2::types::EventKind::Head(h)) => {
                    assert_eq!(h.slot, Slot::new(2));
                }
                other => panic!("Expected head event from stream 1, got: {other:?}"),
            },
            other => panic!(
                "Expected Event from stream 1, got: {:?}",
                match other {
                    StreamEvent::Event(idx, _) => format!("Event from {idx}"),
                    StreamEvent::StreamEnded(idx) => format!("StreamEnded({idx})"),
                }
            ),
        }
    }

    /// Tests that the sentinel `StreamEnded` event is emitted exactly once when a
    /// stream's channel is closed, allowing the consumer to track which stream failed.
    #[tokio::test]
    async fn test_stream_ended_sentinel() {
        let (tx, rx) =
            futures::channel::mpsc::channel::<Result<eth2::types::EventKind<E>, eth2::Error>>(16);
        let mut combined = futures::stream::SelectAll::new();
        combined.push(channel_to_stream(42, rx));

        // Close the channel immediately
        drop(tx);

        // Should get StreamEnded(42) and then SelectAll returns None
        match combined.next().await {
            Some(StreamEvent::StreamEnded(42)) => { /* expected */ }
            other => panic!(
                "Expected StreamEnded(42), got: {:?}",
                other.map(|e| match e {
                    StreamEvent::Event(idx, _) => format!("Event from {idx}"),
                    StreamEvent::StreamEnded(idx) => format!("StreamEnded({idx})"),
                })
            ),
        }

        // SelectAll should now be empty
        assert!(combined.next().await.is_none());
    }
}
