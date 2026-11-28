//! Bounded correlation for application aggregate processing. This is independent of observer
//! experiments. No networking/consensus locks may be held while calling these helpers.
use crate::{Mode, Point, Reference, global};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

const CAPACITY: usize = 16_384;
#[derive(Clone)]
struct Attempt {
    reference: Reference,
    queued: Option<Point>,
    started: Option<Point>,
    finished: Option<Point>,
    closed: bool,
    loss_epoch: u64,
}
struct Receipt {
    topic: String,
    first: Reference,
    current: Attempt,
    vote: Option<Value>,
}
#[derive(Default)]
struct State {
    messages: HashMap<String, Receipt>,
    order: VecDeque<String>,
}
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
// A failed nonblocking hook cannot safely mutate its attempt. Conservatively mark missing
// boundaries in all attempts spanning that loss as unknown, rather than asserting they never ran.
static LOSS_EPOCH: AtomicU64 = AtomicU64::new(0);
fn with_state(f: impl FnOnce(&mut State)) {
    let _ = with_state_result(f);
}
fn with_state_result<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    let recorder = global()?;
    match STATE
        .get_or_init(|| Mutex::new(State::default()))
        .try_lock()
    {
        Ok(mut state) => Some(f(&mut state)),
        Err(_) => {
            LOSS_EPOCH.fetch_add(1, Ordering::Relaxed);
            recorder.record_summary_eviction("pq.aggregate_processed");
            None
        }
    }
}
fn point(value: &Option<Point>, missing: &str) -> Value {
    value
        .as_ref()
        .map_or_else(|| json!({"missing":missing}), |p| json!(p))
}
fn fresh(reference: Reference) -> Attempt {
    Attempt {
        reference,
        queued: None,
        started: None,
        finished: None,
        closed: false,
        loss_epoch: LOSS_EPOCH.load(Ordering::Relaxed),
    }
}
/// IDs are already computed by gossipsub. The caller supplies lowercase 0x hex.
pub fn received(topic: &str, id: &str, uncompressed_bytes: usize) {
    let Some(recorder) = global() else { return };
    let received = recorder.point();
    received_at(topic, id, uncompressed_bytes, received);
}
pub fn received_at(topic: &str, id: &str, uncompressed_bytes: usize, received: Point) {
    let Some(recorder) = global() else { return };
    with_state(|state| {
        if state.messages.contains_key(id) {
            return;
        }
        if state.messages.len() >= CAPACITY
            && let Some(old) = state.order.pop_front()
        {
            state.messages.remove(&old);
            recorder.record_summary_eviction("pq.aggregate_received");
        }
        let attempt = recorder.reference();
        recorder.emit(
            "pq.aggregate_received",
            &received,
            Mode::Production,
            json!({
                "message":{"topic":topic,"gossip_id":id},"attempt":attempt,"received":received,
                "sizes":{"ssz_bytes":uncompressed_bytes}
            }),
        );
        state.order.push_back(id.to_owned());
        state.messages.insert(
            id.to_owned(),
            Receipt {
                topic: topic.to_owned(),
                first: attempt.clone(),
                current: fresh(attempt),
                vote: None,
            },
        );
    });
}
/// Stamp before executor submission. If admission fails, `queue_dropped` removes this tentative
/// stamp, preserving the contract's distinction between attempted and successful admission.
pub fn queued(id: &str) {
    let Some(recorder) = global() else { return };
    let at = recorder.point();
    with_state(|state| {
        if let Some(receipt) = state.messages.get_mut(id) {
            if receipt.current.closed {
                receipt.current = fresh(recorder.reference());
            }
            receipt.current.queued = Some(at);
        }
    });
}
pub fn started(id: &str) {
    let Some(recorder) = global() else { return };
    let at = recorder.point();
    with_state(|state| {
        if let Some(receipt) = state.messages.get_mut(id) {
            if receipt.current.closed {
                receipt.current = fresh(recorder.reference());
            }
            receipt.current.started = Some(at);
        }
    });
}
pub fn finished(id: &str) {
    let Some(recorder) = global() else { return };
    let at = recorder.point();
    with_state(|state| {
        if let Some(receipt) = state.messages.get_mut(id) {
            receipt.current.finished = Some(at);
        }
    });
}
fn complete(
    id: &str,
    validation: &str,
    pool: &str,
    stage: &str,
    reason: &str,
    usable: Option<Point>,
    rejected_admission: bool,
) {
    complete_if(
        id,
        validation,
        pool,
        stage,
        reason,
        usable,
        rejected_admission,
        None,
    );
}
#[allow(clippy::too_many_arguments)]
fn complete_if(
    id: &str,
    validation: &str,
    pool: &str,
    stage: &str,
    reason: &str,
    usable: Option<Point>,
    rejected_admission: bool,
    expected: Option<&Reference>,
) {
    let Some(recorder) = global() else { return };
    let terminal = recorder.point();
    with_state(|state| {
        if let Some(receipt) = state.messages.get_mut(id) {
            let attempt = &mut receipt.current;
            if attempt.closed || expected.is_some_and(|reference| reference != &attempt.reference) {
                return;
            }
            if rejected_admission {
                attempt.queued = None;
            }
            let missing = if attempt.loss_epoch != LOSS_EPOCH.load(Ordering::Relaxed) {
                "not_exposed"
            } else {
                "not_reached"
            };
            if expected.is_some() && missing == "not_exposed" {
                // A fallback Drop guard cannot distinguish cancelled work from a successful
                // terminal hook lost to contention. Leave that result unknown instead of
                // replacing it with an invented queue cancellation.
                attempt.closed = true;
                recorder.record_summary_eviction("pq.aggregate_processed");
                return;
            }
            let queued_missing = if attempt.started.is_some() && attempt.queued.is_none() {
                "not_exposed"
            } else {
                missing
            };
            let mut data = json!({
                "message":{"topic":receipt.topic,"gossip_id":id},"attempt":attempt.reference,"receipt_attempt":receipt.first,
                "queued":point(&attempt.queued,queued_missing),"started":point(&attempt.started,missing),
                "finished":point(&attempt.finished,missing),"usable":point(&usable,if pool=="already_available" {"not_applicable"} else {missing}),
                "validation_outcome":validation,"pool_outcome":pool,"terminal_stage":stage,"reason":reason
            });
            if let Some(vote) = &receipt.vote {
                data["vote"] = vote.clone();
            }
            recorder.emit("pq.aggregate_processed", &terminal, Mode::Production, data);
            attempt.closed = true;
        }
    });
}
pub fn decode_failed(id: &str) {
    complete(
        id,
        "rejected",
        "not_applicable",
        "decode",
        "decode_error",
        None,
        false,
    );
}
pub fn queue_dropped(id: &str) {
    complete(
        id,
        "dropped",
        "not_applicable",
        "queue",
        "queue_full",
        None,
        true,
    );
}
pub fn sync_dropped(id: &str) {
    complete(
        id,
        "dropped",
        "not_applicable",
        "queue",
        "early_gate",
        None,
        false,
    );
}
pub fn validation_failed(id: &str, outcome: &str, reason: &str) {
    complete(
        id,
        outcome,
        "not_applicable",
        "validation",
        reason,
        None,
        false,
    );
}
/// Invoked directly after the production proposal-pool insertion returns.
pub fn pool_result(id: &str, outcome: &str) {
    let Some(recorder) = global() else { return };
    let inserted = outcome == "inserted";
    let usable = inserted.then(|| recorder.point());
    complete(
        id,
        "accepted",
        if inserted {
            "inserted"
        } else if outcome == "covered" {
            "already_available"
        } else {
            "not_inserted"
        },
        "pool",
        if inserted {
            "none"
        } else {
            match outcome {
                "covered" => "already_covered",
                "expired" => "deadline",
                "capacity" => "queue_full",
                "invalid" => "invalid",
                _ => "other",
            }
        },
        usable,
        false,
    );
}
pub fn pool_error(id: &str) {
    complete(id, "accepted", "error", "pool", "pool_error", None, false);
}

// Publication ID capture spans only the synchronous libp2p call.
thread_local! {
    static PUBLICATION_ID: std::cell::RefCell<Option<Option<String>>> = const { std::cell::RefCell::new(None) };
}
pub fn publication_started() -> Option<Point> {
    let recorder = global()?;
    let point = recorder.point();
    PUBLICATION_ID.with(|value| *value.borrow_mut() = Some(None));
    Some(point)
}
/// Observe the ID already computed by the configured libp2p callback, without hashing again.
/// This synchronous scope also retains IDs when publication fails after ID creation.
pub fn observe_message_id(id: &[u8]) {
    if global().is_none() {
        return;
    }
    PUBLICATION_ID.with(|value| {
        if let Some(pending) = value.borrow_mut().as_mut() {
            let mut text = String::from("0x");
            use std::fmt::Write;
            for byte in id {
                let _ = write!(&mut text, "{byte:02x}");
            }
            *pending = Some(text);
        }
    });
}
pub fn publication_id() -> Option<String> {
    PUBLICATION_ID.with(|value| value.borrow_mut().take().flatten())
}

#[allow(clippy::too_many_arguments)]
pub fn published(
    topic: &str,
    id: Option<&str>,
    requested: &Point,
    returned: &Point,
    reason: &str,
    ssz_bytes: usize,
    accepted: bool,
    metadata: Value,
) -> Option<Reference> {
    let recorder = global()?;
    let publication = recorder.reference();
    let message = id.map_or_else(
        || json!({"topic":topic,"missing":"not_created"}),
        |id| json!({"topic":topic,"gossip_id":id}),
    );
    let mut data = json!({
        "message":message,"publication":publication,"requested":requested,"returned":returned,
        "outcome":if accepted{"accepted"}else{"failed"},"reason":reason,"sizes":{"ssz_bytes":ssz_bytes}
    });
    if let (Some(data), Some(metadata)) = (data.as_object_mut(), metadata.as_object()) {
        data.extend(
            metadata
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    recorder.emit("pq.aggregate_published", returned, Mode::Production, data);
    Some(publication)
}

/// Metadata enrichment is deliberately after the receipt timestamp and does not delay it.
pub fn annotate(id: &str, vote: Value) {
    with_state(|state| {
        if let Some(receipt) = state.messages.get_mut(id) {
            receipt.vote = Some(vote);
        }
    });
}

/// Carries a deferred attempt through the existing dependency queue. Dropping a queued callback
/// without executing it closes this attempt as cancelled rather than inventing validation.
pub struct RetryGuard {
    id: String,
    reference: Option<Reference>,
    armed: bool,
}
impl RetryGuard {
    pub fn new(id: String) -> Self {
        // Capture ownership atomically with creating the attempt. A lost capture must never
        // fall back to an unqualified cancellation of whatever later attempt occupies this ID.
        let reference = global().and_then(|recorder| {
            with_state_result(|state| {
                let receipt = state.messages.get_mut(&id)?;
                receipt.current = fresh(recorder.reference());
                Some(receipt.current.reference.clone())
            })
            .flatten()
        });
        Self {
            id,
            reference,
            armed: true,
        }
    }
    pub fn executing(mut self) {
        self.armed = false;
    }
}
impl Drop for RetryGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(reference) = &self.reference
        {
            complete_if(
                &self.id,
                "cancelled",
                "not_applicable",
                "queue",
                "other",
                None,
                false,
                Some(reference),
            );
        }
    }
}

pub fn attempt(id: &str) -> Option<Reference> {
    let mut result = None;
    with_state(|state| {
        result = state.messages.get(id).map(|r| r.current.reference.clone());
    });
    result
}
pub fn abandoned(id: &str, expected: &Reference) {
    complete_if(
        id,
        "cancelled",
        "not_applicable",
        "queue",
        "other",
        None,
        false,
        Some(expected),
    );
}

#[cfg(test)]
pub(crate) fn exercise_test_observation_loss() {
    let topic = "/eth2/01234567/beacon_aggregate_and_proof/ssz_snappy";
    let id = format!("0x{:040x}", 201);
    received(topic, &id, 500);
    queued(&id);
    {
        let _locked = STATE.get().unwrap().lock().unwrap();
        started(&id);
    }
    finished(&id);
    pool_result(&id, "inserted");

    let id = format!("0x{:040x}", 202);
    received(topic, &id, 500);
    queued(&id);
    started(&id);
    {
        let _locked = STATE.get().unwrap().lock().unwrap();
        finished(&id);
    }
    pool_result(&id, "capacity");

    let id = format!("0x{:040x}", 203);
    received(topic, &id, 500);
    queued(&id);
    started(&id);
    finished(&id);
    validation_failed(&id, "deferred", "missing_state");
    let unowned = {
        let _locked = STATE.get().unwrap().lock().unwrap();
        RetryGuard::new(id.clone())
    };
    assert!(unowned.reference.is_none());
    let retry = RetryGuard::new(id.clone());
    let owned = retry.reference.clone().unwrap();
    drop(unowned);
    assert_eq!(attempt(&id), Some(owned));
    assert!(
        !STATE.get().unwrap().lock().unwrap().messages[&id]
            .current
            .closed
    );
    queued(&id);
    retry.executing();
    started(&id);
    finished(&id);
    pool_result(&id, "inserted");

    // Losing the actual successful terminal must not let the package's fallback Drop guard
    // rewrite it as a queue cancellation.
    let id = format!("0x{:040x}", 204);
    received(topic, &id, 500);
    queued(&id);
    started(&id);
    finished(&id);
    let reference = attempt(&id).unwrap();
    {
        let _locked = STATE.get().unwrap().lock().unwrap();
        pool_result(&id, "inserted");
    }
    abandoned(&id, &reference);
}

#[cfg(test)]
pub(crate) fn exercise_test_lifecycle() {
    let topic = "/eth2/01234567/beacon_aggregate_and_proof/ssz_snappy";
    let first = format!("0x{:040x}", 1);
    received(topic, &first, 500);
    received(topic, &first, 500); // The first-receipt record is unique.
    queued(&first);
    started(&first);
    finished(&first);
    pool_result(&first, "inserted");
    for (number, failure) in [
        (2, decode_failed as fn(&str)),
        (3, queue_dropped),
        (4, sync_dropped),
    ] {
        let id = format!("0x{number:040x}");
        received(topic, &id, 500);
        if number != 2 {
            queued(&id);
        }
        failure(&id);
    }
    let id = format!("0x{:040x}", 5);
    received(topic, &id, 500);
    queued(&id);
    started(&id);
    finished(&id);
    let original = attempt(&id).expect("recorded attempt");
    validation_failed(&id, "deferred", "missing_state");
    let retry = RetryGuard::new(id.clone());
    // Dropping the old package must not cancel its new deferred retry.
    abandoned(&id, &original);
    queued(&id);
    retry.executing();
    started(&id);
    finished(&id);
    pool_result(&id, "covered");
    let cancelled = format!("0x{:040x}", 6);
    received(topic, &cancelled, 500);
    queued(&cancelled);
    started(&cancelled);
    finished(&cancelled);
    validation_failed(&cancelled, "deferred", "missing_state");
    drop(RetryGuard::new(cancelled));
    let recorder = global().expect("test installs recorder");
    let requested = publication_started().expect("enabled");
    assert!(publication_id().is_none());
    published(
        topic,
        None,
        &requested,
        &recorder.point(),
        "other",
        500,
        false,
        json!({}),
    );
    let requested = publication_started().expect("enabled");
    observe_message_id(&[9; 20]);
    let id = publication_id().expect("observed existing ID");
    published(
        topic,
        Some(&id),
        &requested,
        &recorder.point(),
        "duplicate_suppressed",
        500,
        false,
        json!({}),
    );
    let requested = publication_started().expect("enabled");
    observe_message_id(&[10; 20]);
    let id = publication_id().expect("observed existing ID");
    published(
        topic,
        Some(&id),
        &requested,
        &recorder.point(),
        "none",
        500,
        true,
        json!({}),
    );
}

/// Resolve an already-observed message without recomputing its identity or retaining payloads.
pub fn message(id: &str) -> Option<Value> {
    let mut result = None;
    with_state(|state| {
        result = state
            .messages
            .get(id)
            .map(|receipt| json!({"topic":receipt.topic,"gossip_id":id}));
    });
    result
}
