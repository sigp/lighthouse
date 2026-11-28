//! Bounded duty and produced-proof correlation shared by production hooks.
use crate::{Mode, Point, Reference, global};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

const LIMIT: usize = 4096;
#[derive(Clone)]
struct Duty {
    reference: Reference,
    revision: u64,
    schedule: Value,
    terminal: bool,
    terminal_outcome: Option<String>,
    submitted: bool,
    details: Value,
    validator: Option<u64>,
    sequence: Reference,
    foreign: bool,
}
#[derive(Default)]
struct Registry {
    duties: BTreeMap<String, Duty>,
    results: BTreeMap<[u8; 32], Reference>,
    messages: BTreeMap<[u8; 32], Value>,
    sequence_attempts: BTreeMap<(String, String), u64>,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(Mutex::default)
}
fn lock() -> Option<std::sync::MutexGuard<'static, Registry>> {
    match registry().try_lock() {
        Ok(guard) => Some(guard),
        Err(_) => {
            if let Some(recorder) = global() {
                recorder.record_summary_eviction("pq.duty_completed");
            }
            None
        }
    }
}

#[cfg(test)]
pub(crate) fn forget_for_test(key: &str) {
    if let Some(mut registry) = lock() {
        registry.duties.remove(key);
    }
}

pub fn committee_key(slot: u64, committee: u64, position: u64) -> String {
    format!("committee:{slot}:{committee}:{position}")
}
pub fn proposal_key(slot: u64) -> String {
    format!("proposal:{slot}")
}

/// The caller has discovered an actual local duty, with its real schedule and geometry.
pub fn schedule(key: String, schedule: Value, validator: Option<u64>) -> Option<(Reference, u64)> {
    let recorder = global()?;
    let point = recorder.point();
    let mut registry = lock()?;
    if let Some(old) = registry.duties.get(&key) {
        if old.foreign {
            return Some((old.reference.clone(), old.revision));
        }
        if old.schedule == schedule
            && old.validator == validator
            && !matches!(
                old.terminal_outcome.as_deref(),
                Some("superseded" | "cancelled")
            )
        {
            return Some((old.reference.clone(), old.revision));
        }
    }
    let (reference, revision) = if let Some(old) = registry.duties.get_mut(&key) {
        if !old.terminal && !old.submitted {
            close(old, &point, "superseded", "reorg", false);
        }
        (old.reference.clone(), old.revision.saturating_add(1))
    } else {
        (recorder.reference(), 0)
    };
    if registry.duties.len() >= LIMIT && !registry.duties.contains_key(&key) {
        registry.duties.pop_first();
        recorder.record_summary_eviction("pq.duty_completed");
    }
    let mut data = schedule.clone();
    data["duty"] = json!(reference);
    data["revision"] = json!(revision);
    data["known"] = json!(point);
    recorder.emit("pq.duty_scheduled", &point, Mode::Production, data);
    registry.duties.insert(
        key,
        Duty {
            reference: reference.clone(),
            revision,
            schedule,
            terminal: false,
            terminal_outcome: None,
            submitted: false,
            details: json!({}),
            validator,
            sequence: recorder.reference(),
            foreign: false,
        },
    );
    Some((reference, revision))
}

pub fn export(key: &str) -> Option<(Reference, u64, Value, Option<u64>)> {
    global()?;
    let registry = lock()?;
    let duty = registry.duties.get(key)?;
    Some((
        duty.reference.clone(),
        duty.revision,
        duty.schedule.clone(),
        duty.validator,
    ))
}

pub fn keys_for_validators(validators: &[u64], kind: &str) -> Vec<String> {
    let Some(recorder) = global() else {
        return vec![];
    };
    let now = recorder.point().unix_ns.parse::<u128>().unwrap_or_default();
    let Some(registry) = lock() else {
        return vec![];
    };
    registry
        .duties
        .iter()
        .filter(|(_, duty)| {
            !duty.terminal
                && duty.schedule["kind"] == kind
                && duty.schedule[if kind == "proposal" {
                    "proposal_unix_ns"
                } else {
                    "broadcast_unix_ns"
                }]
                .as_str()
                .and_then(|v| v.parse::<u128>().ok())
                .is_some_and(|cutoff| cutoff >= now)
                && duty
                    .validator
                    .is_some_and(|validator| validators.contains(&validator))
        })
        .map(|(key, _)| key.clone())
        .take(128)
        .collect()
}

/// A submitted aggregate is normally processed after its nominal broadcast instant. Terminal
/// observations therefore match retained identity, not the future-only preparation lookup.
pub fn committee_suppressed(slot: u64, committee: u64, validator: u64) {
    let Some(recorder) = global() else { return };
    let point = recorder.point();
    if let Some(mut registry) = lock()
        && let Some(duty) = registry.duties.values_mut().find(|duty| {
            !duty.terminal
                && duty.schedule["kind"] == "committee"
                && duty.schedule["slot"] == slot
                && duty.schedule["committee_index"] == committee
                && duty.validator == Some(validator)
        })
    {
        close(duty, &point, "suppressed", "already_covered", false);
    }
}

/// Import only a validated carrier attached to an actual duty request. This does not
/// invent another scheduled event: the referenced VC is the original owner.
pub fn import_reference(
    key: String,
    reference: Reference,
    revision: u64,
    schedule: Value,
    validator: Option<u64>,
) {
    let Some(recorder) = global() else { return };
    let Some(mut registry) = lock() else { return };
    if let Some(old) = registry.duties.get(&key)
        && old.reference == reference
        && old.revision >= revision
    {
        return;
    }
    if let Some(old) = registry.duties.get_mut(&key)
        && !old.terminal
        && !old.foreign
    {
        close(old, &recorder.point(), "superseded", "other", false);
    }
    if registry.duties.len() >= LIMIT && !registry.duties.contains_key(&key) {
        registry.duties.pop_first();
        recorder.record_summary_eviction("pq.duty_completed");
    }
    registry.duties.insert(
        key,
        Duty {
            reference,
            revision,
            schedule,
            terminal: false,
            terminal_outcome: None,
            submitted: false,
            details: json!({}),
            validator,
            sequence: recorder.reference(),
            foreign: true,
        },
    );
}

pub fn get(key: &str) -> Option<(Reference, u64)> {
    global()?;
    let registry = lock()?;
    let duty = registry.duties.get(key)?;
    (!duty.terminal).then(|| (duty.reference.clone(), duty.revision))
}

pub fn sequence(key: &str) -> Option<Reference> {
    global()?;
    lock()?.duties.get(key).map(|duty| duty.sequence.clone())
}

pub fn next_attempt(sequence: &Reference) -> Option<u64> {
    let mut registry = lock()?;
    let key = (sequence.process_id.clone(), sequence.id.clone());
    if registry.sequence_attempts.len() >= LIMIT && !registry.sequence_attempts.contains_key(&key) {
        registry.sequence_attempts.pop_first();
        if let Some(recorder) = global() {
            recorder.record_summary_eviction("pq.operation_admitted");
        }
    }
    let attempts = registry.sequence_attempts.entry(key).or_default();
    *attempts = attempts.saturating_add(1);
    Some(*attempts)
}

/// Attach an observed collection/selection point, never a scheduled timestamp.
pub fn details(key: &str, details: Value) {
    if global().is_none() {
        return;
    }
    if let Some(mut registry) = lock()
        && let Some(duty) = registry.duties.get_mut(key)
        && let (Some(target), Some(extra)) = (duty.details.as_object_mut(), details.as_object())
    {
        target.extend(extra.clone());
    }
}

pub fn complete(key: &str, outcome: &'static str, reason: &'static str, late: bool) {
    let Some(recorder) = global() else { return };
    if let Some(mut registry) = lock()
        && let Some(duty) = registry.duties.get_mut(key)
    {
        // A foreign owner observes its own pre-publication failures. Only the BN
        // can close its actual libp2p publication or explicit coverage suppression.
        if !duty.terminal && !duty.submitted && (!duty.foreign || outcome == "suppressed") {
            close(duty, &recorder.point(), outcome, reason, late)
        }
    }
}

fn close(duty: &mut Duty, point: &Point, outcome: &str, reason: &str, late: bool) {
    let Some(recorder) = global() else { return };
    let kind = duty.schedule["kind"].as_str().unwrap_or("proposal");
    let mut data = json!({"duty":duty.reference,"revision":duty.revision,"kind":kind,
        "slot":duty.schedule["slot"],"terminal":point,"outcome":outcome,"reason":reason,"late":late});
    if kind == "committee" {
        data["collection_closed"] = json!({"missing":"not_reached"});
    } else {
        data["selection_time"] = json!({"missing":"not_reached"});
        data["selected_operations"] = json!([]);
        data["reused_messages"] = json!([]);
    }
    if let (Some(target), Some(extra)) = (data.as_object_mut(), duty.details.as_object()) {
        target.extend(extra.clone());
    }
    recorder.emit("pq.duty_completed", point, Mode::Production, data);
    duty.terminal = true;
    duty.terminal_outcome = Some(outcome.to_owned());
}

pub fn remember_result(proof: &[u8], operation: Reference) {
    let Some(recorder) = global() else { return };
    let digest: [u8; 32] = Sha256::digest(proof).into();
    if let Some(mut registry) = lock() {
        if registry.results.len() >= LIMIT {
            registry.results.pop_first();
            recorder.record_summary_eviction("pq.operation_completed");
        }
        registry.results.insert(digest, operation);
    }
}
pub fn result(proof: &[u8]) -> Option<Reference> {
    global()?;
    let digest: [u8; 32] = Sha256::digest(proof).into();
    lock()?.results.get(&digest).cloned()
}

pub fn remember_message(proof: &[u8], message: Value) {
    let Some(recorder) = global() else { return };
    let digest: [u8; 32] = Sha256::digest(proof).into();
    if let Some(mut registry) = lock() {
        if registry.messages.len() >= LIMIT {
            registry.messages.pop_first();
            recorder.record_summary_eviction("pq.aggregate_received");
        }
        registry.messages.insert(digest, message);
    }
}
pub fn message(proof: &[u8]) -> Option<Value> {
    global()?;
    let digest: [u8; 32] = Sha256::digest(proof).into();
    lock()?.messages.get(&digest).cloned()
}

pub fn publication_metadata(slot: u64, aggregator_index: Option<u64>, proof: &[u8]) -> Value {
    if global().is_none() {
        return json!({});
    }
    let mut data = json!({});
    if let Some(operation) = result(proof) {
        data["operation"] = json!(operation);
    }
    if let Some(registry) = lock()
        && let Some(duty) = registry.duties.values().find(|d| {
            !d.terminal
                && d.schedule["slot"] == slot
                && if let Some(index) = aggregator_index {
                    d.schedule["kind"] == "committee" && d.validator == Some(index)
                } else {
                    d.schedule["kind"] == "proposal"
                }
        })
    {
        data["duty"] = json!(duty.reference);
        data["duty_revision"] = json!(duty.revision);
    }
    data
}

pub fn published(
    slot: u64,
    aggregator_index: Option<u64>,
    _proof: &[u8],
    publication: &Reference,
    requested: &Point,
    returned: &Point,
    accepted: bool,
) {
    if global().is_none() || !accepted {
        return;
    }
    if let Some(mut registry) = lock()
        && let Some(duty) = registry.duties.values_mut().find(|d| {
            !d.terminal
                && d.schedule["slot"] == slot
                && if let Some(index) = aggregator_index {
                    d.schedule["kind"] == "committee" && d.validator == Some(index)
                } else {
                    d.schedule["kind"] == "proposal"
                }
        })
    {
        duty.details["publication"] = json!(publication);
        duty.details["published_at"] = json!(requested);
        let deadline = if aggregator_index.is_some() {
            "broadcast_unix_ns"
        } else {
            "proposal_unix_ns"
        };
        let late = duty.schedule[deadline]
            .as_str()
            .and_then(|v| v.parse::<u128>().ok())
            .is_some_and(|cutoff| {
                requested
                    .unix_ns
                    .parse::<u128>()
                    .is_ok_and(|now| now > cutoff)
            });
        close(duty, returned, "published", "none", late);
    }
}

pub fn proposal_published(slot: u64, requested: &Point, returned: &Point, accepted: bool) {
    if global().is_none() || !accepted {
        return;
    }
    if let Some(mut registry) = lock()
        && let Some(duty) = registry.duties.get_mut(&proposal_key(slot))
        && !duty.terminal
    {
        duty.details["published_at"] = json!(requested);
        let late = duty.schedule["proposal_unix_ns"]
            .as_str()
            .and_then(|v| v.parse::<u128>().ok())
            .is_some_and(|cutoff| {
                requested
                    .unix_ns
                    .parse::<u128>()
                    .is_ok_and(|now| now > cutoff)
            });
        close(duty, returned, "published", "none", late);
    }
}

/// An HTTP publish attempt may have reached a BN even when its response is lost.
/// Later VC retries must not turn this uncertainty into a definite pre-publication failure.
pub fn submitted(key: &str) {
    if global().is_none() {
        return;
    }
    if let Some(mut registry) = lock()
        && let Some(duty) = registry.duties.get_mut(key)
    {
        duty.submitted = true;
    }
}
