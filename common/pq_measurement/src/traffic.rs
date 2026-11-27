//! Fixed-size traffic windows. Callers supply actual complete-copy callbacks from the networking
//! layer; unique application receipts must never be used as a substitute. The integration owns
//! the bounded topic/ring registry and marks interrupted observation explicitly.

use crate::{MAX_COUNT, Mode, Point, Recorder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const BUCKET_NS: u64 = 100_000_000;
pub const WINDOW_NS: u64 = 1_000_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scope {
    pub code_location: String,
    pub payload_encoding: Encoding,
    pub copy_basis: CopyBasis,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Compressed,
    Uncompressed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CopyBasis {
    AllReceivedCopies,
    PerRecipient,
    Unavailable,
}

impl Scope {
    pub fn unavailable(code_location: impl Into<String>) -> Self {
        Self {
            code_location: code_location.into(),
            payload_encoding: Encoding::Unavailable,
            copy_basis: CopyBasis::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    Rx,
    Tx,
}

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    payload_bytes: u64,
    message_copies: u64,
    lost: bool,
}

impl Counts {
    fn add(&mut self, bytes: u64) {
        match (
            self.payload_bytes.checked_add(bytes),
            self.message_copies.checked_add(1),
        ) {
            (Some(bytes), Some(copies)) if bytes <= MAX_COUNT && copies <= MAX_COUNT => {
                self.payload_bytes = bytes;
                self.message_copies = copies;
            }
            _ => self.lost = true,
        }
    }
    fn value(self, scope: &Scope) -> Value {
        if scope.copy_basis == CopyBasis::Unavailable {
            json!({"missing":"not_exposed"})
        } else if self.lost {
            json!({"missing":"not_observed"})
        } else {
            json!({"payload_bytes":self.payload_bytes, "message_copies":self.message_copies})
        }
    }
}

/// One topic/one second. All storage has a fixed bound independent of message volume.
pub struct Window {
    topic: String,
    start: Point,
    rx_scope: Scope,
    tx_scope: Scope,
    rx: [Counts; 10],
    tx: [Counts; 10],
}

impl Window {
    pub fn new(
        topic: String,
        start: Point,
        rx_scope: Scope,
        tx_scope: Scope,
    ) -> Result<Self, String> {
        if topic.is_empty()
            || start.mono_ns.parse::<u64>().is_err()
            || rx_scope.copy_basis == CopyBasis::PerRecipient
            || tx_scope.copy_basis == CopyBasis::AllReceivedCopies
        {
            return Err("invalid traffic window topic, time, or directional copy scope".into());
        }
        Ok(Self {
            topic,
            start,
            rx_scope,
            tx_scope,
            rx: [Counts::default(); 10],
            tx: [Counts::default(); 10],
        })
    }

    /// Counts a whole payload in the callback's half-open bucket. A callback is a single
    /// successful peer queue handoff for TX, or a pre-dedup decoder delivery for RX.
    pub fn observe(&mut self, direction: Direction, at: &Point, payload_bytes: u64) -> bool {
        let Some(elapsed) = at.elapsed_ns_since(&self.start) else {
            return false;
        };
        if elapsed >= WINDOW_NS {
            return false;
        }
        let index = (elapsed / BUCKET_NS) as usize;
        let counts = match direction {
            Direction::Rx => &mut self.rx,
            Direction::Tx => &mut self.tx,
        };
        if let Some(count) = counts.get_mut(index) {
            count.add(payload_bytes);
            true
        } else {
            false
        }
    }

    /// Startup/shutdown/gaps in a supported callback must be explicit, never observed zero.
    pub fn mark_not_observed(&mut self, direction: Direction, bucket: usize) {
        let counts = match direction {
            Direction::Rx => &mut self.rx,
            Direction::Tx => &mut self.tx,
        };
        if let Some(count) = counts.get_mut(bucket) {
            count.lost = true;
        }
    }

    pub fn data(&self) -> Value {
        json!({ "topic":self.topic, "window_start":self.start, "bucket_ns":BUCKET_NS.to_string(),
            "rx_scope":self.rx_scope, "tx_scope":self.tx_scope,
            "buckets":self.rx.iter().zip(self.tx.iter()).map(|(rx,tx)| json!({"rx":rx.value(&self.rx_scope), "tx":tx.value(&self.tx_scope)})).collect::<Vec<_>>() })
    }

    /// The close is the nominal boundary mapped from the observer's fixed paired anchor.
    /// Refuse future/partial windows. A driver retains a fixed monotonic origin between windows.
    pub fn emit(self, recorder: &Recorder, close: &Point, observed_now: &Point) -> bool {
        if close.elapsed_ns_since(&self.start) != Some(WINDOW_NS)
            || observed_now.elapsed_ns_since(close).is_none()
        {
            return false;
        }
        recorder.emit("pq.aggregate_traffic", close, Mode::Production, self.data())
    }
}

/// An immutable allowlist entry. A collector never creates topics from incoming traffic.
#[derive(Clone, Debug)]
pub struct Topic {
    pub name: String,
    pub rx_scope: Scope,
    pub tx_scope: Scope,
}

pub const MAX_TOPICS: usize = 32;
pub const MAX_RETAINED_WINDOWS: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_topics: usize,
    /// Time windows, each containing every allowlisted topic (not per-topic records).
    pub retained_windows: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_topics: MAX_TOPICS,
            retained_windows: MAX_RETAINED_WINDOWS,
        }
    }
}

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Default)]
struct TopicCounts {
    rx: [Counts; 10],
    tx: [Counts; 10],
}
impl TopicCounts {
    fn direction(&mut self, direction: Direction) -> &mut [Counts; 10] {
        match direction {
            Direction::Rx => &mut self.rx,
            Direction::Tx => &mut self.tx,
        }
    }
    fn lose(&mut self, direction: Direction) {
        for bucket in self.direction(direction) {
            bucket.lost = true;
        }
    }
}

struct Batch {
    index: u64,
    topics: [TopicCounts; MAX_TOPICS],
}
impl Batch {
    fn empty(index: u64) -> Self {
        Self {
            index,
            topics: [TopicCounts::default(); MAX_TOPICS],
        }
    }
}

/// Numeric collection state: no JSON, event IDs, strings or per-copy retained objects.
struct Driver {
    current: Batch,
    completed: VecDeque<Batch>,
    capacity: usize,
    topic_count: usize,
}
impl Driver {
    fn new(capacity: usize, topic_count: usize) -> Self {
        Self {
            current: Batch::empty(0),
            completed: VecDeque::with_capacity(capacity),
            capacity,
            topic_count,
        }
    }

    /// Advance by monotonic time. At most `capacity` iterations, even after a long stall.
    /// Return discarded logical topic-window records for visible loss accounting.
    fn advance(&mut self, elapsed: u64) -> u64 {
        let target = elapsed / WINDOW_NS;
        let delta = target.saturating_sub(self.current.index);
        if delta == 0 {
            return 0;
        }
        let mut evicted = 0_u64;
        if delta > self.capacity as u64 {
            evicted = (self.completed.len() as u64)
                .saturating_add(delta.saturating_sub(self.capacity as u64));
            self.completed.clear();
            for index in target.saturating_sub(self.capacity as u64)..target {
                self.completed.push_back(Batch::empty(index));
            }
            self.current = Batch::empty(target);
        } else {
            for _ in 0..delta {
                let next = self.current.index.saturating_add(1);
                let completed = std::mem::replace(&mut self.current, Batch::empty(next));
                if self.completed.len() >= self.capacity {
                    self.completed.pop_front();
                    evicted = evicted.saturating_add(1);
                }
                self.completed.push_back(completed);
            }
        }
        evicted.saturating_mul(self.topic_count as u64)
    }

    fn lose(&mut self, topic: usize, direction: Direction) {
        if let Some(counts) = self.current.topics.get_mut(topic) {
            counts.lose(direction);
        }
        for window in &mut self.completed {
            if let Some(counts) = window.topics.get_mut(topic) {
                counts.lose(direction);
            }
        }
    }

    fn observe(&mut self, topic: usize, direction: Direction, elapsed: u64, bytes: u64) -> bool {
        if elapsed / WINDOW_NS != self.current.index {
            return false;
        }
        let bucket = ((elapsed % WINDOW_NS) / BUCKET_NS) as usize;
        let Some(counts) = self
            .current
            .topics
            .get_mut(topic)
            .and_then(|counts| counts.direction(direction).get_mut(bucket))
        else {
            return false;
        };
        let was_lost = counts.lost;
        counts.add(bytes);
        !was_lost && counts.lost
    }
}

#[derive(Clone)]
struct Anchor {
    process_id: String,
    mono_ns: u64,
    unix_ns: u64,
}
impl Anchor {
    fn new(point: Point) -> Result<Self, String> {
        Ok(Self {
            process_id: point.process_id,
            mono_ns: point
                .mono_ns
                .parse()
                .map_err(|_| "invalid traffic monotonic anchor")?,
            unix_ns: point
                .unix_ns
                .parse()
                .map_err(|_| "invalid traffic UTC anchor")?,
        })
    }
    fn boundary(&self, index: u64) -> Option<Point> {
        let offset = index.checked_mul(WINDOW_NS)?;
        Some(Point {
            process_id: self.process_id.clone(),
            mono_ns: self.mono_ns.checked_add(offset)?.to_string(),
            unix_ns: self.unix_ns.checked_add(offset)?.to_string(),
        })
    }
}

/// Bounded complete-copy collection for one network polling task.
///
/// The decoder callbacks, peer-queue callbacks, `tick` and `shutdown` MUST run on the same
/// network polling task. `Arc` is for callback ownership, not an extra collection worker.
/// A try-lock is defensive: unexpected contention loses observation, never waits for a duty.
/// The next successful access conservatively invalidates that direction across all retained
/// windows because the exact interval cannot safely be recovered after a missed callback.
/// This is intentionally broader than one bucket, rather than exporting surviving partial totals.
pub struct Collector {
    recorder: Arc<Recorder>,
    topics: Vec<Topic>,
    anchor: Anchor,
    state: Mutex<Driver>,
    losses: [[AtomicU64; 2]; MAX_TOPICS],
    pending_loss: AtomicBool,
    stopped: AtomicBool,
}
impl Collector {
    pub fn new(
        recorder: Arc<Recorder>,
        topics: Vec<Topic>,
        limits: Limits,
    ) -> Result<Arc<Self>, String> {
        if limits.max_topics == 0
            || limits.max_topics > MAX_TOPICS
            || limits.retained_windows == 0
            || limits.retained_windows > MAX_RETAINED_WINDOWS
            || topics.is_empty()
            || topics.len() > limits.max_topics
        {
            return Err(
                "traffic collector requires 1..32 topics and 1..8 retained time windows".into(),
            );
        }
        for (index, topic) in topics.iter().enumerate() {
            if topic.name.is_empty()
                || topic.name.len() > 512
                || topics
                    .iter()
                    .take(index)
                    .any(|prior| prior.name == topic.name)
                || !valid_scope(&topic.rx_scope, Direction::Rx)
                || !valid_scope(&topic.tx_scope, Direction::Tx)
            {
                return Err("invalid or duplicate traffic topic/copy scope".into());
            }
        }
        let state = Driver::new(limits.retained_windows, topics.len());
        // One paired capture for the lifetime of this observer. Never re-read UTC for labels.
        let anchor = Anchor::new(recorder.point())?;
        Ok(Arc::new(Self {
            recorder,
            topics,
            anchor,
            state: Mutex::new(state),
            losses: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            pending_loss: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        }))
    }

    /// Whole compressed/uncompressed payload bytes as specified by this topic's scopes.
    /// Unknown topics and callbacks after shutdown are ignored without allocating.
    pub fn observe(&self, direction: Direction, topic: &str, payload_bytes: usize) {
        if self.stopped.load(Ordering::Relaxed) {
            return;
        }
        let Some(index) = self.topics.iter().position(|entry| entry.name == topic) else {
            return;
        };
        let now = self.recorder.monotonic_ns();
        self.observe_at(direction, index, payload_bytes as u64, now);
    }

    fn observe_at(&self, direction: Direction, topic: usize, payload_bytes: u64, now: u64) {
        let Ok(mut state) = self.state.try_lock() else {
            self.note_loss(topic, direction);
            return;
        };
        let Some(elapsed) = now.checked_sub(self.anchor.mono_ns) else {
            state.lose(topic, direction);
            self.recorder
                .record_summary_eviction("pq.aggregate_traffic");
            return;
        };
        let evicted = state.advance(elapsed);
        self.recorder
            .record_summary_evictions("pq.aggregate_traffic", evicted);
        self.apply_losses(&mut state);
        if elapsed / WINDOW_NS != state.current.index {
            state.lose(topic, direction);
            self.recorder
                .record_summary_eviction("pq.aggregate_traffic");
        } else if state.observe(topic, direction, elapsed, payload_bytes) {
            self.recorder
                .record_summary_eviction("pq.aggregate_traffic");
        }
    }

    fn note_loss(&self, topic: usize, direction: Direction) {
        if let Some(loss) = self
            .losses
            .get(topic)
            .and_then(|pair| pair.get(direction_index(direction)))
        {
            // Only a marker is needed: repeated missed observations keep the same interval unknown.
            loss.store(1, Ordering::Release);
            self.pending_loss.store(true, Ordering::Release);
        }
        self.recorder
            .record_summary_eviction("pq.aggregate_traffic");
    }

    fn apply_losses(&self, state: &mut Driver) {
        if !self.pending_loss.swap(false, Ordering::AcqRel) {
            return;
        }
        for (topic, directions) in self.losses.iter().take(self.topics.len()).enumerate() {
            for (index, loss) in directions.iter().enumerate() {
                if loss.swap(0, Ordering::AcqRel) != 0 {
                    state.lose(
                        topic,
                        if index == 0 {
                            Direction::Rx
                        } else {
                            Direction::Tx
                        },
                    );
                }
            }
        }
    }

    /// Called once per second by the network polling task; idle full windows are exported too.
    pub fn tick(&self) {
        if !self.stopped.load(Ordering::Relaxed) {
            self.flush_at(self.recorder.monotonic_ns());
        }
    }

    /// Flush only nominally completed windows. The partial final window remains unknown.
    pub fn shutdown(&self) {
        self.shutdown_at(self.recorder.monotonic_ns());
    }

    fn shutdown_at(&self, now: u64) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            self.flush_at(now);
        }
    }

    fn flush_at(&self, now: u64) {
        let Ok(mut state) = self.state.try_lock() else {
            // This violates the single-task contract. Conservatively invalidate all directions.
            for index in 0..self.topics.len() {
                self.note_loss(index, Direction::Rx);
                self.note_loss(index, Direction::Tx);
            }
            return;
        };
        let Some(elapsed) = now.checked_sub(self.anchor.mono_ns) else {
            return;
        };
        let evicted = state.advance(elapsed);
        self.recorder
            .record_summary_evictions("pq.aggregate_traffic", evicted);
        self.apply_losses(&mut state);
        let completed = state.completed.drain(..).collect::<Vec<_>>();
        drop(state);
        // No collector lock is held while building JSON or admitting records to the exporter.
        for batch in completed {
            let Some(start) = self.anchor.boundary(batch.index) else {
                self.recorder
                    .record_summary_evictions("pq.aggregate_traffic", self.topics.len() as u64);
                continue;
            };
            let Some(close) = batch
                .index
                .checked_add(1)
                .and_then(|index| self.anchor.boundary(index))
            else {
                self.recorder
                    .record_summary_evictions("pq.aggregate_traffic", self.topics.len() as u64);
                continue;
            };
            for (topic, counts) in self.topics.iter().zip(batch.topics.iter()) {
                let window = Window {
                    topic: topic.name.clone(),
                    start: start.clone(),
                    rx_scope: topic.rx_scope.clone(),
                    tx_scope: topic.tx_scope.clone(),
                    rx: counts.rx,
                    tx: counts.tx,
                };
                // Derived nominal close, not timer wakeup or export time. advance guarantees closed.
                self.recorder.emit(
                    "pq.aggregate_traffic",
                    &close,
                    Mode::Production,
                    window.data(),
                );
            }
        }
    }
}

fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::Rx => 0,
        Direction::Tx => 1,
    }
}
fn valid_scope(scope: &Scope, direction: Direction) -> bool {
    if scope.code_location.is_empty() {
        return false;
    }
    match scope.copy_basis {
        CopyBasis::Unavailable => scope.payload_encoding == Encoding::Unavailable,
        CopyBasis::AllReceivedCopies => {
            matches!(direction, Direction::Rx) && scope.payload_encoding != Encoding::Unavailable
        }
        CopyBasis::PerRecipient => {
            matches!(direction, Direction::Tx) && scope.payload_encoding != Encoding::Unavailable
        }
    }
}

#[cfg(test)]
#[path = "traffic_tests.rs"]
mod collector_tests;
