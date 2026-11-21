//! Bounded local event export. Serialization and compression run on the writer thread.

use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

const QUEUE: usize = 16_384;
const ROTATE_BYTES: usize = 64 << 20;
const RETAIN_BYTES: u64 = 8 << 30;
const ROTATE_TIME: Duration = Duration::from_secs(300);
const STATUS_INTERVAL: Duration = Duration::from_secs(10);
const CLASS_COUNT: usize = 4;

#[derive(Clone, Copy, Debug)]
pub(super) enum Class {
    Receipt,
    Validation,
    Work,
    Status,
}

impl Class {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::Validation => "validation",
            Self::Work => "work",
            Self::Status => "status",
        }
    }
}

#[derive(Serialize)]
pub(super) struct Record {
    pub kind: &'static str,
    pub wall_ns: u64,
    pub mono_ns: u64,
    #[serde(flatten)]
    pub fields: Value,
}

#[derive(Default)]
struct Health {
    failed: AtomicBool,
    next_seq: AtomicU64,
    drops: [AtomicU64; CLASS_COUNT],
    dropped_first: AtomicU64,
    dropped_last: AtomicU64,
    drop_wall_first: AtomicU64,
    drop_wall_last: AtomicU64,
}

impl Health {
    fn status(&self) -> Value {
        let first = self.dropped_first.load(Ordering::Relaxed);
        json!({
            "disk_failed": self.failed.load(Ordering::Relaxed),
            "dropped": {
                "receipt": self.drops[Class::Receipt as usize].load(Ordering::Relaxed),
                "validation": self.drops[Class::Validation as usize].load(Ordering::Relaxed),
                "work": self.drops[Class::Work as usize].load(Ordering::Relaxed),
                "status": self.drops[Class::Status as usize].load(Ordering::Relaxed),
            },
            "first_dropped_sequence": (first != 0).then_some(first),
            "last_dropped_sequence": self.dropped_last.load(Ordering::Relaxed),
            "submitted_sequence": self.next_seq.load(Ordering::Relaxed),
            "first_dropped_wall_ns": self.drop_wall_first.load(Ordering::Relaxed),
            "last_dropped_wall_ns": self.drop_wall_last.load(Ordering::Relaxed),
        })
    }

    fn drop_event(&self, seq: u64, wall: u64, class: Class) {
        let _ = self
            .dropped_first
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |first| {
                Some(if first == 0 { seq } else { first.min(seq) })
            });
        self.dropped_last.fetch_max(seq, Ordering::Relaxed);
        let _ = self
            .drop_wall_first
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |first| {
                Some(if first == 0 { wall } else { first.min(wall) })
            });
        self.drop_wall_last.fetch_max(wall, Ordering::Relaxed);
        self.drops[class as usize].fetch_add(1, Ordering::Relaxed);
        crate::metrics::inc_counter_vec(&super::RECORDER_EVENTS, &[class.label(), "dropped"]);
    }
}

#[derive(Serialize)]
struct Envelope {
    seq: u64,
    #[serde(flatten)]
    record: Record,
}

pub(super) struct Recorder {
    sender: Option<SyncSender<Envelope>>,
    thread: Option<thread::JoinHandle<()>>,
    health: Arc<Health>,
}

impl Recorder {
    pub(super) fn open(root: &Path, id: &str, mut metadata: Value) -> Result<Self, String> {
        let path = root.join(id);
        fs::create_dir_all(root).map_err(|error| format!("PQ timing output: {error}"))?;
        fs::create_dir(&path).map_err(|error| format!("PQ timing run directory: {error}"))?;
        let health = Arc::new(Health::default());
        metadata["recorder_status"] = health.status();
        metadata["chunks"] = json!([]);
        write_metadata(&path, &metadata)
            .map_err(|error| format!("PQ timing run metadata: {error}"))?;
        tracing::info!(run_dir = %path.display(), "Recording PQ timing locally");
        let (sender, receiver) = sync_channel(QUEUE);
        let reporter = Arc::clone(&health);
        let thread = thread::Builder::new()
            .name("pq-timing-writer".to_string())
            .spawn(move || {
                if let Err(error) = write_events(&path, &receiver, &reporter, &mut metadata) {
                    reporter.failed.store(true, Ordering::Release);
                    crate::metrics::inc_counter_vec(
                        &super::RECORDER_EVENTS,
                        &["status", "disk_error"],
                    );
                    tracing::error!(?error, "PQ timing export disabled after a writer error");
                    metadata["recorder_status"] = reporter.status();
                    if let Err(error) = write_metadata(&path, &metadata) {
                        tracing::warn!(?error, "Unable to record PQ timing export failure");
                    }
                }
            })
            .map_err(|error| format!("PQ timing writer: {error}"))?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
            health,
        })
    }

    pub(super) fn healthy(&self) -> bool {
        !self.health.failed.load(Ordering::Acquire)
    }

    pub(super) fn emit(&self, class: Class, record: Record) {
        let seq = self
            .health
            .next_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if let Some(sender) = &self.sender {
            match sender.try_send(Envelope { seq, record }) {
                Ok(()) => {}
                Err(TrySendError::Full(event) | TrySendError::Disconnected(event)) => {
                    self.health.drop_event(seq, event.record.wall_ns, class);
                }
            }
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Chunk {
    temporary: PathBuf,
    name: String,
    stream: zstd::stream::write::Encoder<'static, BufWriter<File>>,
    started: Instant,
    bytes: usize,
    first: u64,
    last: u64,
}

impl Chunk {
    fn new(path: &Path, number: u64) -> io::Result<Self> {
        let name = format!("events-{number:06}.jsonl.zst");
        let temporary = path.join(format!("{name}.partial"));
        let stream =
            zstd::stream::write::Encoder::new(BufWriter::new(File::create(&temporary)?), 1)?;
        Ok(Self {
            temporary,
            name,
            stream,
            started: Instant::now(),
            bytes: 0,
            first: u64::MAX,
            last: 0,
        })
    }

    fn write(&mut self, event: &Envelope, buffer: &mut Vec<u8>) -> io::Result<()> {
        buffer.clear();
        serde_json::to_writer(&mut *buffer, event)?;
        buffer.push(b'\n');
        self.stream.write_all(buffer)?;
        self.bytes = self.bytes.saturating_add(buffer.len());
        self.first = self.first.min(event.seq);
        self.last = self.last.max(event.seq);
        Ok(())
    }

    fn finish(self, path: &Path) -> io::Result<ChunkInfo> {
        let mut file = self.stream.finish()?;
        file.flush()?;
        let bytes = file.get_ref().metadata()?.len();
        fs::rename(&self.temporary, path.join(&self.name))?;
        Ok(ChunkInfo {
            name: self.name,
            bytes,
            first: self.first,
            last: self.last,
        })
    }
}

#[derive(Serialize)]
struct ChunkInfo {
    name: String,
    bytes: u64,
    first: u64,
    last: u64,
}

fn write_metadata(path: &Path, metadata: &Value) -> io::Result<()> {
    let temp = path.join("run.json.partial");
    let mut file = BufWriter::new(File::create(&temp)?);
    serde_json::to_writer_pretty(&mut file, metadata)?;
    file.write_all(b"\n")?;
    file.flush()?;
    fs::rename(temp, path.join("run.json"))
}

fn write_events(
    path: &Path,
    receiver: &Receiver<Envelope>,
    health: &Health,
    metadata: &mut Value,
) -> io::Result<()> {
    let mut current = None::<Chunk>;
    let mut number = 0u64;
    let mut retained = VecDeque::<ChunkInfo>::new();
    let mut retained_bytes = 0u64;
    let mut evicted_chunks = 0u64;
    let mut evicted_first = u64::MAX;
    let mut evicted_last = 0u64;
    let mut buffer = Vec::new();
    let mut last_status = Instant::now();
    loop {
        let closing = match receiver.recv_timeout(STATUS_INTERVAL) {
            Ok(event) => {
                if current.is_none() {
                    number = number.saturating_add(1);
                    current = Some(Chunk::new(path, number)?);
                }
                if let Some(chunk) = current.as_mut() {
                    chunk.write(&event, &mut buffer)?;
                }
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true,
        };
        let rotate = current.as_ref().is_some_and(|chunk| {
            closing || chunk.bytes >= ROTATE_BYTES || chunk.started.elapsed() >= ROTATE_TIME
        });
        if rotate && let Some(chunk) = current.take() {
            let chunk = chunk.finish(path)?;
            retained_bytes = retained_bytes.saturating_add(chunk.bytes);
            retained.push_back(chunk);
            while retained_bytes > RETAIN_BYTES && retained.len() > 1 {
                if let Some(old) = retained.pop_front() {
                    fs::remove_file(path.join(&old.name))?;
                    retained_bytes = retained_bytes.saturating_sub(old.bytes);
                    evicted_chunks = evicted_chunks.saturating_add(1);
                    evicted_first = evicted_first.min(old.first);
                    evicted_last = evicted_last.max(old.last);
                }
            }
        }
        if rotate || closing || last_status.elapsed() >= STATUS_INTERVAL {
            metadata["chunks"] = json!(retained);
            metadata["recorder_status"] = health.status();
            metadata["recorder_status"]["evicted_chunks"] = json!(evicted_chunks);
            metadata["recorder_status"]["evicted_sequence_bounds"] =
                json!((evicted_chunks != 0).then_some([evicted_first, evicted_last]));
            metadata["recorder_status"]["checked_unix_ns"] = json!(super::wall_now_ns());
            if closing {
                metadata["ended_unix_ns"] = json!(super::wall_now_ns());
            }
            write_metadata(path, metadata)?;
            last_status = Instant::now();
        }
        if closing {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_export_finalizes_a_readable_chunk() {
        let root = tempfile::tempdir().unwrap();
        let recorder = Recorder::open(root.path(), "test", json!({"schema_version": 1})).unwrap();
        recorder.emit(
            Class::Status,
            Record {
                kind: "proposal_snapshot",
                wall_ns: 9,
                mono_ns: 8,
                fields: json!({"round": 2}),
            },
        );
        drop(recorder);
        let run = root.path().join("test");
        let metadata: Value =
            serde_json::from_reader(File::open(run.join("run.json")).unwrap()).unwrap();
        assert!(metadata["ended_unix_ns"].is_number());
        let name = metadata["chunks"][0]["name"].as_str().unwrap();
        let bytes = zstd::stream::decode_all(File::open(run.join(name)).unwrap()).unwrap();
        let event: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(event["round"], 2);
        assert_eq!(event["seq"], 1);
    }

    #[test]
    fn saturated_export_accounts_for_gaps_without_waiting() {
        let (sender, receiver) = sync_channel(1);
        let recorder = Recorder {
            sender: Some(sender),
            thread: None,
            health: Arc::default(),
        };
        for _ in 0..3 {
            recorder.emit(
                Class::Receipt,
                Record {
                    kind: "message_received",
                    wall_ns: 1,
                    mono_ns: 2,
                    fields: json!({}),
                },
            );
        }
        assert_eq!(receiver.try_recv().unwrap().seq, 1);
        assert_eq!(recorder.health.status()["dropped"]["receipt"], 2);
        assert_eq!(recorder.health.status()["first_dropped_sequence"], 2);
        assert_eq!(recorder.health.status()["last_dropped_sequence"], 3);
    }
}
