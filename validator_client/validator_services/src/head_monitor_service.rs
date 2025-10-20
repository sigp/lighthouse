use beacon_node_fallback::{BeaconHeadCache, BeaconNodeFallback};
use eth2::types::EventTopic;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

use eth2::types::EventKind;
use futures::StreamExt;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use validator_store::ValidatorStore;

// Builder for `HeadMonitorService`
#[derive(Default)]
pub struct HeadMonitorServiceBuilder<S: ValidatorStore, T: SlotClock + 'static> {
    validator_store: Option<Arc<S>>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T>>>,
    executor: Option<TaskExecutor>,
    beacon_head_cache: Option<Arc<BeaconHeadCache>>,
    head_monitor_tx: Option<Arc<mpsc::Sender<HeadEvent>>>,
}

// This is used send the index derived from `CandidateBeaconNode` to the
// `AttestationService` for further processing
#[derive(Debug)]
pub struct HeadEvent {
    pub beacon_node_index: usize,
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> HeadMonitorServiceBuilder<S, T> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            beacon_nodes: None,
            executor: None,
            beacon_head_cache: None,
            head_monitor_tx: None,
        }
    }

    pub fn beacon_nodes(mut self, nodes: Arc<BeaconNodeFallback<T>>) -> Self {
        self.beacon_nodes = Some(nodes);
        self
    }

    pub fn executor(mut self, executor: TaskExecutor) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn validator_store(mut self, validator_store: Arc<S>) -> Self {
        self.validator_store = Some(validator_store);
        self
    }

    pub fn beacon_head_cache(mut self, beacon_head_cache: Arc<BeaconHeadCache>) -> Self {
        self.beacon_head_cache = Some(beacon_head_cache);
        self
    }

    pub fn head_monitor_tx(mut self, head_monitor_tx: Arc<mpsc::Sender<HeadEvent>>) -> Self {
        self.head_monitor_tx = Some(head_monitor_tx);
        self
    }
    pub fn build(self) -> Result<HeadMonitorService<S, T>, String> {
        Ok(HeadMonitorService {
            inner: Arc::new(Inner {
                _validator_store: self
                    .validator_store
                    .ok_or("Cannot build HeadMonitorService without validator_store")?,
                beacon_nodes: self
                    .beacon_nodes
                    .ok_or("Cannot build HeadMonitorService without beacon_nodes")?,
                executor: self
                    .executor
                    .ok_or("Cannot build HeadMonitorService without executor")?,
                beacon_head_cache: self
                    .beacon_head_cache
                    .ok_or("Cannot build HeadMonitorService without beacon_head_cache")?,
                head_monitor_tx: self
                    .head_monitor_tx
                    .ok_or("Cannot build HeadMonitorService without head_monitor_rx")?,
            }),
        })
    }
}

// Helper to minimise `Arc` usage
pub struct Inner<S, T> {
    _validator_store: Arc<S>,
    executor: TaskExecutor,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    beacon_head_cache: Arc<BeaconHeadCache>,
    head_monitor_tx: Arc<mpsc::Sender<HeadEvent>>,
}

// Runs a non-terminating loop to update the `BeaconHeadCache` with the latest head received
// from the candidate beacon_nodes. This is an attempt to stream events to beacon nodes and
// potential start attestion duties earlier as soon as latest head is receive from any of the
// beacon node in contrast to attest at the 1/3rd mark in the slot.
//
//
// The cache and the candidate BNs list are refresh/purged to avoid dangling reference conditions
// that arise due to `update_candidates_list`. The cache is refresh use the shared reference between
// `HeadMonitorService` and `BeaconNodeFallback`.
pub struct HeadMonitorService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for HeadMonitorService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for HeadMonitorService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> HeadMonitorService<S, T> {
    // Starts the service to perpetually stream head events from connected beacon_nodes
    pub fn start_update_service(self) -> Result<(), String> {
        let executor = self.executor.clone();
        let head_cache = self.beacon_head_cache.clone();

        info!("Starting head monitoring service");
        let interval_fut = async move {
            loop {
                let candidates = {
                    let candidates_guard = self.beacon_nodes.candidates.read().await;
                    candidates_guard.clone()
                };
                let mut tasks = vec![];

                for candidate in candidates.iter() {
                    let head_event_stream = candidate
                        .beacon_node
                        .get_events::<S::E>(&[EventTopic::Head])
                        .await;

                    let mut head_event_stream = match head_event_stream {
                        Ok(stream) => stream,
                        Err(e) => {
                            warn!("failed to get head event stream: {:?}", e);
                            continue;
                        }
                    };

                    let head_cache_clone = head_cache.clone();
                    let sender_tx = self.head_monitor_tx.clone();

                    let stream_fut = async move {
                        while let Some(event_result) = head_event_stream.next().await {
                            if let Ok(EventKind::Head(head)) = event_result {
                                head_cache_clone.insert(candidate.index, head.clone()).await;

                                if head_cache_clone.is_latest(&head).await {
                                    if let Ok(()) = sender_tx
                                        .send(HeadEvent {
                                            beacon_node_index: candidate.index,
                                        })
                                        .await
                                    {
                                    } else {
                                        warn!("Head monitoring service channel closed");
                                        break;
                                    }
                                }
                            }
                        }
                    };

                    tasks.push(stream_fut);
                }

                if tasks.is_empty() {
                    warn!(
                        "No beacon nodes available for head event streaming, retrying in 5 seconds"
                    );
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }

                futures::future::join_all(tasks).await;

                drop(candidates);
                self.beacon_head_cache.purge_cache().await;

                // Add a small delay before reconnecting to avoid hammering beacon nodes
                sleep(Duration::from_secs(1)).await;
            }
        };

        executor.spawn(interval_fut, "head_monitor_service");

        Ok(())
    }
}
