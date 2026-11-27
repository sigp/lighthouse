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

    /// The close is the actual paired boundary reading, supplied by the collection driver.
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
