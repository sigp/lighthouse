//! Dedicated, bounded PQ measurements. This does not install a tracing subscriber or an
//! OpenTelemetry global provider. Hooks capture clocks before building their JSON body and use
//! `try_send`; collector connectivity never lies on the duty execution path.

pub mod client;
pub mod duty;
pub mod gossip;
pub mod handoff;
pub mod proof;
#[cfg(test)]
mod tests;
pub mod traffic;
mod transport;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, mpsc};
use url::Url;

pub const SCHEMA_VERSION: &str = "pq.measurement/0.1-draft3";
pub const MAX_COUNT: u64 = (1_u64 << 53) - 1;
pub const EVENT_NAMES: [&str; 10] = [
    "pq.context",
    "pq.aggregate_received",
    "pq.aggregate_processed",
    "pq.aggregate_published",
    "pq.validation_batch",
    "pq.operation_admitted",
    "pq.operation_completed",
    "pq.duty_scheduled",
    "pq.duty_completed",
    "pq.aggregate_traffic",
];

static GLOBAL: OnceLock<Arc<Recorder>> = OnceLock::new();
static GENERATED: LazyLock<metrics::Result<metrics::IntCounterVec>> = LazyLock::new(|| {
    metrics::try_create_int_counter_vec(
        "pq_measurement_generated_total",
        "Logical PQ records generated, excluding transport retries",
        &["event"],
    )
});
static DROPPED: LazyLock<metrics::Result<metrics::IntCounterVec>> = LazyLock::new(|| {
    metrics::try_create_int_counter_vec(
        "pq_measurement_dropped_total",
        "PQ records lost or with unconfirmed delivery",
        &["event"],
    )
});
static EVICTED: LazyLock<metrics::Result<metrics::IntCounterVec>> = LazyLock::new(|| {
    metrics::try_create_int_counter_vec(
        "pq_measurement_summary_evictions_total",
        "PQ measurement correlation/summary observations lost",
        &["event"],
    )
});
static EXPORT_ERRORS: LazyLock<metrics::Result<metrics::IntCounter>> = LazyLock::new(|| {
    metrics::try_create_int_counter(
        "pq_measurement_export_errors_total",
        "Failed or partially rejected PQ export requests",
    )
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Production,
    Experiment,
    Replay,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Experiment => "experiment",
            Self::Replay => "replay",
        }
    }
}

/// Paired wall/monotonic readings. Strings preserve nanoseconds through JSON and OTLP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Point {
    pub process_id: String,
    pub unix_ns: String,
    pub mono_ns: String,
}

impl Point {
    /// No duration can be inferred between clocks from different process starts.
    pub fn elapsed_ns_since(&self, earlier: &Self) -> Option<u64> {
        if self.process_id != earlier.process_id {
            return None;
        }
        self.mono_ns
            .parse::<u64>()
            .ok()?
            .checked_sub(earlier.mono_ns.parse().ok()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub process_id: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub schema_version: String,
    pub event_name: String,
    pub node_id: String,
    pub process_id: String,
    pub event_seq: u64,
    pub context_id: String,
    pub timestamp_unix_ns: String,
    pub mode: Mode,
    pub data: Value,
}

/// Validate without opening a connection. Explicit ports are required, including default ports.
pub fn validate_endpoint(endpoint: &str) -> Result<Url, String> {
    let parsed = Url::parse(endpoint).map_err(|_| "invalid PQ measurement OTLP URL".to_string())?;
    let authority = endpoint
        .split_once("://")
        .map(|(_, s)| s.split('/').next().unwrap_or_default())
        .unwrap_or_default();
    let explicit_port = authority
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok());
    if endpoint.trim() != endpoint
        || !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || explicit_port.is_none_or(|p| p == 0)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || authority.contains('@')
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("PQ measurement endpoint requires http:// or https://, a host and explicit port, and no credentials, path, query or fragment".into());
    }
    Ok(parsed)
}

#[derive(Debug, Clone)]
pub struct Config {
    pub endpoint: String,
    pub node_id: String,
    pub context_id: String,
    /// Immutable canonical `pq.context` body. Client integration supplies actual hook semantics.
    pub context_data: Value,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub max_record_bytes: usize,
    pub export_timeout: Duration,
    pub flush_interval: Duration,
}

impl Config {
    pub fn new(
        endpoint: impl Into<String>,
        node_id: impl Into<String>,
        context_id: impl Into<String>,
        context_data: Value,
    ) -> Result<Self, String> {
        let config = Self {
            endpoint: endpoint.into(),
            node_id: node_id.into(),
            context_id: context_id.into(),
            context_data,
            queue_capacity: 2048,
            batch_size: 32,
            max_record_bytes: 65_536,
            export_timeout: Duration::from_secs(2),
            flush_interval: Duration::from_secs(1),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        validate_endpoint(&self.endpoint)?;
        if self.node_id.is_empty()
            || self.context_id.is_empty()
            || !self.context_data.is_object()
            || self.queue_capacity == 0
            || self.queue_capacity > 65_536
            || self.batch_size == 0
            || self.batch_size > 256
            || self.max_record_bytes == 0
            || self.max_record_bytes > 1_048_576
            || self.export_timeout.is_zero()
            || self.flush_interval.is_zero()
        {
            return Err("invalid PQ measurement identity or bounded exporter configuration".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FamilyCounters {
    pub generated: u64,
    pub dropped: u64,
    pub summary_evictions: u64,
}

#[derive(Debug, Clone)]
pub struct Counters {
    pub families: Vec<(&'static str, FamilyCounters)>,
    pub export_errors: u64,
    pub queue_depth: usize,
}

#[derive(Debug, Default)]
struct FamilyAtomic {
    generated: AtomicU64,
    dropped: AtomicU64,
    evicted: AtomicU64,
}

#[derive(Debug, Default)]
pub(crate) struct Health {
    families: [FamilyAtomic; 10],
    export_errors: AtomicU64,
}

impl Health {
    fn generated(&self, index: usize) {
        if let (Some(f), Some(name)) = (self.families.get(index), EVENT_NAMES.get(index)) {
            f.generated.fetch_add(1, Ordering::Relaxed);
            metrics::inc_counter_vec(&GENERATED, &[name]);
        }
    }
    pub(crate) fn dropped(&self, index: usize, count: u64) {
        if let (Some(f), Some(name)) = (self.families.get(index), EVENT_NAMES.get(index)) {
            f.dropped.fetch_add(count, Ordering::Relaxed);
            metrics::inc_counter_vec_by(&DROPPED, &[name], count);
        }
    }
    pub(crate) fn export_error(&self) {
        self.export_errors.fetch_add(1, Ordering::Relaxed);
        metrics::inc_counter(&EXPORT_ERRORS);
    }
}

pub struct Recorder {
    process_id: String,
    node_id: String,
    context_id: String,
    origin: Instant,
    next_seq: AtomicU64,
    next_ref: AtomicU64,
    max_record_bytes: usize,
    sender: mpsc::Sender<Record>,
    health: Arc<Health>,
    stopped: Arc<AtomicBool>,
    stop: Arc<Notify>,
    finished: Arc<Notify>,
    done: Arc<AtomicBool>,
}

impl Recorder {
    /// Requires an entered Tokio runtime; connection establishment remains asynchronous/lazy.
    pub fn start(config: Config) -> Result<Arc<Self>, String> {
        config.validate()?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| "PQ measurement exporter requires a Tokio runtime")?;
        let client = transport::client(&config)?;
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let recorder = Arc::new(Self {
            process_id: uuid::Uuid::new_v4().to_string(),
            node_id: config.node_id.clone(),
            context_id: config.context_id.clone(),
            origin: Instant::now(),
            next_seq: AtomicU64::new(1),
            next_ref: AtomicU64::new(0),
            max_record_bytes: config.max_record_bytes,
            sender,
            health: Arc::new(Health::default()),
            stopped: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(Notify::new()),
            finished: Arc::new(Notify::new()),
            done: Arc::new(AtomicBool::new(false)),
        });
        let context = recorder.record(
            "pq.context",
            0,
            &recorder.point(),
            Mode::Production,
            config.context_data.clone(),
        );
        if !valid_body(&context.data, config.max_record_bytes) {
            return Err(
                "PQ measurement context exceeds export limits or contains unsupported JSON values"
                    .into(),
            );
        }
        recorder.health.generated(0);
        tokio::spawn(transport::run(
            client,
            config,
            receiver,
            context,
            recorder.health.clone(),
            recorder.stop.clone(),
            recorder.finished.clone(),
            recorder.done.clone(),
        ));
        Ok(recorder)
    }

    pub fn process_id(&self) -> &str {
        &self.process_id
    }
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    pub fn point(&self) -> Point {
        // Re-read UTC at every boundary so wall-clock steps remain observable.
        let wall = SystemTime::now();
        let mono = self.origin.elapsed();
        Point {
            process_id: self.process_id.clone(),
            unix_ns: unix_ns(wall).to_string(),
            mono_ns: duration_ns(mono).to_string(),
        }
    }

    pub fn new_id(&self) -> String {
        match self
            .next_ref
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        {
            Ok(n) => n.to_string(),
            // Never reuse a local ID even after exhausting the counter.
            Err(_) => uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn reference(&self) -> Reference {
        Reference {
            process_id: self.process_id.clone(),
            id: self.new_id(),
        }
    }

    /// Assign a logical record identity before attempting bounded admission. False means lost.
    pub fn emit(&self, event_name: &'static str, at: &Point, mode: Mode, data: Value) -> bool {
        let Some(index) = EVENT_NAMES.iter().position(|n| *n == event_name) else {
            return false;
        };
        self.health.generated(index);
        let sequence = self
            .next_seq
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < MAX_COUNT).then(|| n.saturating_add(1))
            });
        let Ok(sequence) = sequence else {
            self.health.dropped(index, 1);
            return false;
        };
        if self.stopped.load(Ordering::Relaxed)
            || at.unix_ns.parse::<u64>().is_err()
            || at.process_id != self.process_id
            || !valid_body(&data, self.max_record_bytes)
        {
            self.health.dropped(index, 1);
            return false;
        }
        if self
            .sender
            .try_send(self.record(event_name, sequence, at, mode, data))
            .is_err()
        {
            self.health.dropped(index, 1);
            false
        } else {
            true
        }
    }

    fn record(
        &self,
        event_name: &str,
        event_seq: u64,
        at: &Point,
        mode: Mode,
        data: Value,
    ) -> Record {
        Record {
            schema_version: SCHEMA_VERSION.into(),
            event_name: event_name.into(),
            node_id: self.node_id.clone(),
            process_id: self.process_id.clone(),
            event_seq,
            context_id: self.context_id.clone(),
            timestamp_unix_ns: at.unix_ns.clone(),
            mode,
            data,
        }
    }

    pub fn record_summary_eviction(&self, family: &'static str) {
        if let Some(index) = EVENT_NAMES.iter().position(|n| *n == family)
            && let Some(f) = self.health.families.get(index)
        {
            f.evicted.fetch_add(1, Ordering::Relaxed);
            metrics::inc_counter_vec(&EVICTED, &[family]);
        }
    }

    pub fn snapshot(&self) -> Counters {
        Counters {
            families: EVENT_NAMES
                .iter()
                .zip(self.health.families.iter())
                .map(|(name, f)| {
                    (
                        *name,
                        FamilyCounters {
                            generated: f.generated.load(Ordering::Relaxed),
                            dropped: f.dropped.load(Ordering::Relaxed),
                            summary_evictions: f.evicted.load(Ordering::Relaxed),
                        },
                    )
                })
                .collect(),
            export_errors: self.health.export_errors.load(Ordering::Relaxed),
            queue_depth: self
                .sender
                .max_capacity()
                .saturating_sub(self.sender.capacity()),
        }
    }

    /// Stop accepting records and drain already admitted records. The caller chooses its own
    /// shutdown deadline; exporter failure never prevents process shutdown.
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.stopped.store(true, Ordering::Relaxed);
        self.stop.notify_one();
        let completed = self.finished.notified();
        tokio::pin!(completed);
        completed.as_mut().enable();
        self.done.load(Ordering::Acquire) || tokio::time::timeout(timeout, completed).await.is_ok()
    }
}

pub fn install_global(recorder: Arc<Recorder>) -> Result<(), Arc<Recorder>> {
    GLOBAL.set(recorder)
}
pub fn global() -> Option<&'static Arc<Recorder>> {
    GLOBAL.get()
}
pub fn point() -> Option<Point> {
    global().map(|r| r.point())
}
pub fn emit(event_name: &'static str, at: &Point, mode: Mode, data: Value) -> bool {
    global().is_some_and(|r| r.emit(event_name, at, mode, data))
}

pub(crate) fn unix_ns(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(duration_ns)
        .unwrap_or_default()
}
fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

// Bounded traversal rejects null/floating point/nonrepresentable integer values rather than
// silently changing their type in protobuf. Charge for container/allocator overhead and worst
// case JSON escaping without serializing on a duty thread. This is deliberately conservative.
fn valid_body(value: &Value, budget: usize) -> bool {
    fn visit(value: &Value, remaining: &mut usize, depth: usize) -> bool {
        if depth > 32 || *remaining < 128 {
            return false;
        }
        *remaining = remaining.saturating_sub(128);
        match value {
            Value::Null => false,
            Value::Bool(_) => true,
            Value::Number(n) => n.as_i64().is_some_and(|v| v.unsigned_abs() <= MAX_COUNT),
            Value::String(s) => {
                let charge = s.len().saturating_mul(6);
                let fits = charge <= *remaining;
                *remaining = remaining.saturating_sub(charge);
                fits
            }
            Value::Array(values) => values
                .iter()
                .all(|v| visit(v, remaining, depth.saturating_add(1))),
            Value::Object(values) => values.iter().all(|(k, v)| {
                let charge = k.len().saturating_mul(6).saturating_add(128);
                if charge > *remaining {
                    return false;
                }
                *remaining = remaining.saturating_sub(charge);
                visit(v, remaining, depth.saturating_add(1))
            }),
        }
    }
    let mut remaining = budget;
    value.is_object() && visit(value, &mut remaining, 0)
}
