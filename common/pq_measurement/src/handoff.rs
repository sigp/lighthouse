//! Optional measurement-only context carried over the existing VC/BN HTTP requests.
//! Invalid or oversized context is ignored; it never changes request validity or duty execution.
use crate::{MAX_COUNT, Reference, duty, global};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const HEADER: &str = "x-lighthouse-pq-measurement";
const MAX_BYTES: usize = 16 * 1024;
const MAX_ENTRIES: usize = 128;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub duty: Reference,
    pub revision: u64,
    pub schedule: Value,
    pub validator_index: Option<u64>,
}
impl Entry {
    pub fn slot(&self) -> Option<u64> {
        self.schedule["slot"].as_u64()
    }
    pub fn committee(&self) -> Option<u64> {
        self.schedule["committee_index"].as_u64()
    }
    pub fn is_proposal(&self) -> bool {
        self.schedule["kind"] == "proposal"
    }
    fn key(&self) -> Option<String> {
        Some(if self.is_proposal() {
            duty::proposal_key(self.slot()?)
        } else {
            duty::committee_key(
                self.slot()?,
                self.committee()?,
                self.schedule["aggregator_position"].as_u64()?,
            )
        })
    }
    fn valid(&self) -> bool {
        if uuid::Uuid::parse_str(&self.duty.process_id).is_err()
            || self.duty.id.is_empty()
            || self.duty.id.len() > 128
            || self.revision > MAX_COUNT
            || self.validator_index.is_none_or(|v| v > MAX_COUNT)
        {
            return false;
        }
        let Some(map) = self.schedule.as_object() else {
            return false;
        };
        if map.keys().any(|key| {
            !matches!(
                key.as_str(),
                "kind"
                    | "slot"
                    | "collection_unix_ns"
                    | "broadcast_unix_ns"
                    | "proposal_unix_ns"
                    | "aggregator_position"
                    | "committee_index"
                    | "committee_members"
                    | "committees_per_slot"
            )
        }) {
            return false;
        }
        if self.slot().is_none_or(|v| v > MAX_COUNT) {
            return false;
        }
        let number = |name: &str, min: u64| {
            self.schedule[name]
                .as_u64()
                .is_some_and(|v| v >= min && v <= MAX_COUNT)
        };
        let time = |name: &str| {
            self.schedule[name].as_str().is_some_and(|v| {
                !v.is_empty()
                    && v.len() <= 19
                    && (v == "0" || !v.starts_with('0'))
                    && v.bytes().all(|b| b.is_ascii_digit())
            })
        };
        if self.is_proposal() {
            time("proposal_unix_ns")
        } else {
            self.schedule["kind"] == "committee"
                && number("committee_index", 0)
                && number("aggregator_position", 0)
                && number("committee_members", 1)
                && number("committees_per_slot", 1)
                && time("collection_unix_ns")
                && time("broadcast_unix_ns")
        }
    }
}
pub fn encode(keys: &[String]) -> Option<String> {
    let recorder = global()?;
    let mut output = String::from("[");
    let mut count = 0;
    for key in keys.iter().take(MAX_ENTRIES) {
        if let Some((reference, revision, schedule, validator)) = duty::export(key) {
            let entry = Entry {
                duty: reference,
                revision,
                schedule,
                validator_index: validator,
            };
            let encoded = serde_json::to_string(&entry).ok()?;
            if output.len().saturating_add(encoded.len()).saturating_add(2) > MAX_BYTES {
                recorder.record_summary_eviction("pq.duty_scheduled");
                break;
            }
            if count > 0 {
                output.push(',');
            }
            output.push_str(&encoded);
            count += 1;
        }
    }
    if keys.len() > MAX_ENTRIES {
        recorder.record_summary_eviction("pq.duty_scheduled");
    }
    output.push(']');
    (count > 0).then_some(output)
}
/// The endpoint additionally binds each entry to the validator/slot/committee in its real body.
pub fn import(header: &str, allowed: impl Fn(&Entry) -> bool) {
    let Some(recorder) = global() else { return };
    let entries = if header.len() <= MAX_BYTES {
        serde_json::from_str::<Vec<Entry>>(header).ok()
    } else {
        None
    };
    let Some(entries) = entries.filter(|v| v.len() <= MAX_ENTRIES) else {
        recorder.record_summary_eviction("pq.duty_scheduled");
        return;
    };
    for entry in entries {
        if !entry.valid() || !allowed(&entry) {
            recorder.record_summary_eviction("pq.duty_scheduled");
            continue;
        }
        if let Some(key) = entry.key() {
            duty::import_reference(
                key,
                entry.duty,
                entry.revision,
                entry.schedule,
                entry.validator_index,
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed_or_unbounded_handoff() {
        let mut entry = Entry {
            duty: Reference {
                process_id: "11111111-1111-4111-8111-111111111111".into(),
                id: "1".into(),
            },
            revision: 0,
            validator_index: Some(1),
            schedule: serde_json::json!({"kind":"committee","slot":5,"committee_index":0,"aggregator_position":0,"committee_members":128,"committees_per_slot":16,"collection_unix_ns":"100","broadcast_unix_ns":"200"}),
        };
        assert!(entry.valid());
        entry.schedule["committee_members"] = serde_json::json!(0);
        assert!(!entry.valid());
        entry.schedule["committee_members"] = serde_json::json!(128);
        entry.schedule["unknown"] = serde_json::json!(1);
        assert!(!entry.valid());
    }
}

/// Exercise real carrier serialization and registry transfer in the single-global integration
/// harness. This models separate process registries; it is not a live two-process HTTP test.
#[cfg(test)]
pub(crate) fn exercise_test_ownership() -> (Reference, Reference) {
    use crate::{
        Mode,
        proof::{Call, Plan},
    };
    use serde_json::json;
    let recorder = global().expect("integration test installs recorder");
    let key = duty::committee_key(900, 0, 0);
    let now = recorder.point();
    let base = now.unix_ns.parse::<u64>().unwrap();
    let owner=duty::schedule(key.clone(),json!({"kind":"committee","slot":900,
        "committee_index":0,"committee_members":2,"committees_per_slot":1,"aggregator_position":0,
        "collection_unix_ns":base.to_string(),"broadcast_unix_ns":base.saturating_add(1_000_000_000).to_string()}),Some(42)).unwrap();
    let header = encode(std::slice::from_ref(&key)).unwrap();
    let scheduled = recorder
        .snapshot()
        .families
        .iter()
        .find(|(family, _)| *family == "pq.duty_scheduled")
        .unwrap()
        .1
        .generated;
    duty::forget_for_test(&key);
    assert!(duty::get(&key).is_none());
    import(&header, |entry| {
        entry.slot() == Some(900)
            && entry.committee() == Some(0)
            && entry.validator_index == Some(42)
    });
    assert_eq!(duty::get(&key), Some(owner.clone()));
    // Registering the real BN duty must preserve its imported VC owner and not schedule twice.
    let schedule = duty::export(&key).unwrap().2;
    assert_eq!(
        duty::schedule(key.clone(), schedule, Some(42)),
        Some(owner.clone())
    );
    assert_eq!(
        recorder
            .snapshot()
            .families
            .iter()
            .find(|(family, _)| *family == "pq.duty_scheduled")
            .unwrap()
            .1
            .generated,
        scheduled
    );
    duty::details(
        &key,
        json!({"collection_closed":recorder.point(),"available_signers":2,"selected_signers":2}),
    );
    let plan = Plan::new(
        Mode::Production,
        json!({"kind":"committee","purpose":"committee_duty","vote_slot":900,
        "committee_index":0,"committee_members":2,"committees_per_slot":1,"signatures":2}),
        duty::get(&key),
    )
    .unwrap();
    plan.messages([([7; 32], 900)]);
    let mut call = Call::start(0, 2, &[[7; 32]]).unwrap();
    call.backend_finished();
    call.returned(100);
    let operation = plan.ready("committee").unwrap();
    drop(plan);
    duty::remember_result(b"handoff-proof", operation.clone());
    let metadata = duty::publication_metadata(900, Some(42), b"handoff-proof");
    assert_eq!(metadata["duty"], json!(owner.0));
    assert_eq!(metadata["duty_revision"], json!(owner.1));
    assert_eq!(metadata["operation"], json!(operation));
    let requested = recorder.point();
    let returned = recorder.point();
    let publication = crate::gossip::published(
        "/eth2/01234567/beacon_aggregate_and_proof/ssz_snappy",
        Some("0x7777777777777777777777777777777777777777"),
        &requested,
        &returned,
        "none",
        500,
        true,
        metadata,
    )
    .unwrap();
    duty::published(
        900,
        Some(42),
        b"handoff-proof",
        &publication,
        &requested,
        &returned,
        true,
    );
    assert!(duty::get(&key).is_none());
    (owner.0, operation)
}
