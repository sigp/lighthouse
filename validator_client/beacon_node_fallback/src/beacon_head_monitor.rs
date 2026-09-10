use crate::{BeaconNodeFallback, CandidateBeaconNode};
use eth2::Error as Eth2Error;
use eth2::types::{EventKind, EventTopic, Hash256, SseHead};
use futures::StreamExt;
use futures::stream::BoxStream;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};
use types::EthSpec;

type CacheHashMap = HashMap<usize, SseHead>;

/// Bounding `get_events` ensures reconnect attempts don't hang forever (e.g. if a BN is down or
/// restarting and never completes the SSE handshake).
const EVENT_STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// Removes the cached head for a specific beacon node.
    pub async fn remove(&self, beacon_node_index: usize) -> Option<SseHead> {
        self.cache.write().await.remove(&beacon_node_index)
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
    let mut generation_rx = beacon_nodes
        .head_monitor_generation_tx
        .as_ref()
        .ok_or("Unable to start head monitor without head_monitor_generation_tx")?
        .subscribe();

    info!("Starting head monitoring service");
    let candidates = {
        let candidates_guard = beacon_nodes.candidates.read().await;
        candidates_guard.clone()
    };

    // Clear the cache in case it contains stale data from a previous run. This function gets
    // restarted if it fails (see monitoring in `start_fallback_updater_service`).
    head_cache.purge_cache().await;

    if candidates.is_empty() {
        return Err("No beacon nodes available for head event streaming".to_string());
    }

    // Retry per-slot by default to avoid log spam and align with the VC's main duty cadence.
    let retry_delay = beacon_nodes.spec.get_slot_duration();

    // Create Vec of streams, which we will select over.
    let mut streams = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        streams.push(head_event_stream_for_candidate::<E>(
            candidate,
            head_cache.clone(),
            retry_delay,
        ));
    }

    // Combine streams into a single stream and poll events from any of them.
    let mut combined_stream = futures::stream::select_all(streams);

    loop {
        tokio::select! {
            _ = generation_rx.changed() => {
                // The candidates have been re-enumerated. Restart the head monitor so we don't
                // retain stale indices or cache entries from the previous run.
                let generation = *generation_rx.borrow();
                info!(
                    generation,
                    "Candidate list updated, restarting head monitoring service"
                );
                head_cache.purge_cache().await;
                return Ok(());
            }
            maybe_event = combined_stream.next() => {
                let Some((candidate_index, event)) = maybe_event else {
                    return Err("Head monitoring stream ended unexpectedly".into());
                };

                match event {
                    EventKind::Head(head) => {
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
                    other => {
                        warn!(
                            event_kind = other.topic_name(),
                            candidate_index,
                            "Received unexpected event from BN"
                        );
                    }
                }
            }
        }
    }
}

struct CandidateHeadStreamState<E: EthSpec, F> {
    candidate_index: usize,
    head_cache: Arc<BeaconHeadCache>,
    retry_delay: Duration,
    connect: F,
    consecutive_failures: u64,
    events_stream: Option<BoxStream<'static, Result<EventKind<E>, Eth2Error>>>,
}

fn head_event_stream_for_candidate<E: EthSpec>(
    candidate: CandidateBeaconNode,
    head_cache: Arc<BeaconHeadCache>,
    retry_delay: Duration,
) -> BoxStream<'static, (usize, EventKind<E>)> {
    let candidate_index = candidate.index;
    let beacon_node = candidate.beacon_node;

    head_event_stream_for_candidate_with_connector::<E, _, _>(
        candidate_index,
        head_cache,
        retry_delay,
        move || {
            let beacon_node = beacon_node.clone();
            async move {
                beacon_node
                    .get_events::<E>(&[EventTopic::Head])
                    .await
                    .map(|s| s.boxed())
            }
        },
    )
}

fn head_event_stream_for_candidate_with_connector<E, F, Fut>(
    candidate_index: usize,
    head_cache: Arc<BeaconHeadCache>,
    retry_delay: Duration,
    connect: F,
) -> BoxStream<'static, (usize, EventKind<E>)>
where
    E: EthSpec,
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<
            Output = Result<BoxStream<'static, Result<EventKind<E>, Eth2Error>>, Eth2Error>,
        > + Send
        + 'static,
{
    futures::stream::unfold(
        CandidateHeadStreamState {
            candidate_index,
            head_cache,
            retry_delay,
            connect,
            consecutive_failures: 0,
            events_stream: None,
        },
        |mut state| async move {
            loop {
                // (Re-)connect to the BN event stream if we don't currently have one.
                if state.events_stream.is_none() {
                    match timeout(EVENT_STREAM_CONNECT_TIMEOUT, (state.connect)()).await {
                        Ok(Ok(stream)) => {
                            state.events_stream = Some(stream);
                        }
                        Ok(Err(e)) => {
                            state.consecutive_failures =
                                state.consecutive_failures.saturating_add(1);
                            if state.consecutive_failures.is_power_of_two() {
                                warn!(
                                    error = ?e,
                                    node_index = state.candidate_index,
                                    failures = state.consecutive_failures,
                                    "Failed to get head event stream, will retry"
                                );
                            } else {
                                debug!(
                                    error = ?e,
                                    node_index = state.candidate_index,
                                    failures = state.consecutive_failures,
                                    "Failed to get head event stream, will retry"
                                );
                            }
                            state.head_cache.remove(state.candidate_index).await;
                            sleep(state.retry_delay).await;
                            continue;
                        }
                        Err(e) => {
                            state.consecutive_failures =
                                state.consecutive_failures.saturating_add(1);
                            if state.consecutive_failures.is_power_of_two() {
                                warn!(
                                    error = ?e,
                                    node_index = state.candidate_index,
                                    failures = state.consecutive_failures,
                                    "Timed out getting head event stream, will retry"
                                );
                            } else {
                                debug!(
                                    error = ?e,
                                    node_index = state.candidate_index,
                                    failures = state.consecutive_failures,
                                    "Timed out getting head event stream, will retry"
                                );
                            }
                            state.head_cache.remove(state.candidate_index).await;
                            sleep(state.retry_delay).await;
                            continue;
                        }
                    }
                }

                // Read the next event. Any stream end/error triggers a retry.
                let stream = state
                    .events_stream
                    .as_mut()
                    .expect("events_stream must be Some after connect");

                match stream.next().await {
                    Some(Ok(event)) => {
                        if state.consecutive_failures != 0 {
                            debug!(
                                node_index = state.candidate_index,
                                failures = state.consecutive_failures,
                                "Head event stream recovered"
                            );
                            state.consecutive_failures = 0;
                        }
                        return Some(((state.candidate_index, event), state));
                    }
                    Some(Err(e)) => {
                        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                        if state.consecutive_failures.is_power_of_two() {
                            warn!(
                                error = ?e,
                                node_index = state.candidate_index,
                                failures = state.consecutive_failures,
                                "Head event stream error, will retry"
                            );
                        } else {
                            debug!(
                                error = ?e,
                                node_index = state.candidate_index,
                                failures = state.consecutive_failures,
                                "Head event stream error, will retry"
                            );
                        }
                        state.events_stream = None;
                        state.head_cache.remove(state.candidate_index).await;
                        sleep(state.retry_delay).await;
                        continue;
                    }
                    None => {
                        // Stream end can happen during normal BN restarts or SSE server behavior.
                        // Treat it as debug noise and rely on warnings for actual errors/timeouts.
                        debug!(
                            node_index = state.candidate_index,
                            "Head event stream ended, will retry"
                        );
                        state.events_stream = None;
                        state.head_cache.remove(state.candidate_index).await;
                        sleep(state.retry_delay).await;
                        continue;
                    }
                }
            }
        },
    )
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::FixedBytesExtended;
    use sensitive_url::SensitiveUrl;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use types::MainnetEthSpec;
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
    async fn test_remove_removes_only_the_requested_entry() {
        let cache = BeaconHeadCache::new();
        let head_1 = create_sse_head(1, 1);
        let head_2 = create_sse_head(2, 2);

        cache.insert(0, head_1.clone()).await;
        cache.insert(1, head_2.clone()).await;

        assert_eq!(cache.remove(0).await, Some(head_1));
        assert!(cache.get(0).await.is_none());
        assert_eq!(cache.get(1).await, Some(head_2));
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

    #[tokio::test]
    async fn head_event_stream_reconnects_after_stream_end() {
        type E = MainnetEthSpec;

        let cache = Arc::new(BeaconHeadCache::new());

        // Pre-populate the cache so we can assert it gets cleared on stream end.
        cache.insert(0, create_sse_head(999, 9)).await;

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_cloned = connect_calls.clone();

        let stream = head_event_stream_for_candidate_with_connector::<E, _, _>(
            0,
            cache.clone(),
            Duration::from_millis(0),
            move || {
                let n = connect_calls_cloned.fetch_add(1, Ordering::SeqCst);
                async move {
                    let head = match n {
                        0 => create_sse_head(1, 1),
                        1 => create_sse_head(2, 2),
                        _ => create_sse_head(3, 3),
                    };
                    Ok(futures::stream::iter(vec![Ok(EventKind::Head(head))]).boxed())
                }
            },
        );

        let events: Vec<_> = stream.take(2).collect().await;
        assert_eq!(events.len(), 2);

        assert_eq!(events[0].0, 0);
        assert_eq!(events[1].0, 0);

        match &events[0].1 {
            EventKind::Head(head) => assert_eq!(head.slot, types::Slot::new(1)),
            _ => panic!("unexpected event kind"),
        }
        match &events[1].1 {
            EventKind::Head(head) => assert_eq!(head.slot, types::Slot::new(2)),
            _ => panic!("unexpected event kind"),
        }

        // Should have connected twice: once for each short-lived stream.
        assert_eq!(connect_calls.load(Ordering::SeqCst), 2);

        // Stream end should trigger cache removal.
        assert!(cache.get(0).await.is_none());
    }

    #[tokio::test]
    async fn head_event_stream_retries_after_connect_error() {
        type E = MainnetEthSpec;

        let cache = Arc::new(BeaconHeadCache::new());
        cache.insert(0, create_sse_head(999, 9)).await;

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let connect_calls_cloned = connect_calls.clone();

        let stream = head_event_stream_for_candidate_with_connector::<E, _, _>(
            0,
            cache.clone(),
            Duration::from_millis(0),
            move || {
                let n = connect_calls_cloned.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        return Err(Eth2Error::InvalidUrl(
                            SensitiveUrl::parse("http://example.invalid").unwrap(),
                        ));
                    }
                    Ok(
                        futures::stream::iter(vec![Ok(EventKind::Head(create_sse_head(1, 1)))])
                            .boxed(),
                    )
                }
            },
        );

        let events: Vec<_> = stream.take(1).collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, 0);

        // Should have attempted to connect at least twice (first fails, second succeeds).
        assert!(connect_calls.load(Ordering::SeqCst) >= 2);

        // Connect error should trigger cache removal.
        assert!(cache.get(0).await.is_none());
    }
}
