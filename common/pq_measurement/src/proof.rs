//! Per-native-call measurements, scoped to an existing blocking preparation job.
//!
//! The scope never crosses an await. A native return is held until its actual consumer
//! installs the result. Starting another call consumes the preceding intermediate result.
use crate::{Mode, Point, Reference, global};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

thread_local! {
    static CURRENT: RefCell<Option<Rc<RefCell<State>>>> = const { RefCell::new(None) };
}

struct State {
    mode: Mode,
    workload: Value,
    duty: Option<(Reference, u64)>,
    plan: Reference,
    calls: u64,
    pending: Option<Value>,
    last: Option<Reference>,
    messages: BTreeMap<[u8; 32], u64>,
    drop_reason: &'static str,
}

/// A scope for one fixed-input preparation plan, on its existing blocking worker.
pub struct Plan {
    state: Rc<RefCell<State>>,
    previous: Option<Rc<RefCell<State>>>,
}

/// A finished call transferred out of its blocking worker, awaiting its consumer.
/// Dropping it (including an async timeout) reports a discarded result, never readiness.
pub struct Completion {
    record: Option<Value>,
    mode: Mode,
    operation: Option<Reference>,
}

impl Completion {
    pub fn ready(mut self, kind: &'static str) -> Option<Reference> {
        let recorder = global()?;
        let point = recorder.point();
        if let Some(mut record) = self.record.take() {
            record["ready"] = json!(point);
            record["terminal"] = json!(point);
            record["ready_kind"] = json!(kind);
            record["outcome"] = json!("success");
            record["reason"] = json!("none");
            if record["workload"]["kind"] == "merge" {
                record["plan_ready"] = json!(point);
            }
            recorder.emit("pq.operation_completed", &point, self.mode, record);
        }
        self.operation.take()
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        let Some(recorder) = global() else { return };
        if let Some(mut record) = self.record.take() {
            let point = recorder.point();
            record["terminal"] = json!(point);
            record["outcome"] = json!("discarded_late");
            record["reason"] = json!("deadline");
            if record["workload"]["kind"] == "merge" {
                record["plan_ready"] = json!({"missing":"not_reached"});
            }
            recorder.emit("pq.operation_completed", &point, self.mode, record);
        }
    }
}

impl Plan {
    pub fn new(mode: Mode, workload: Value, duty: Option<(Reference, u64)>) -> Option<Self> {
        let recorder = global()?;
        let state = Rc::new(RefCell::new(State {
            mode,
            workload,
            duty,
            plan: recorder.reference(),
            calls: 0,
            pending: None,
            last: None,
            messages: BTreeMap::new(),
            drop_reason: "other",
        }));
        let previous = CURRENT.with(|current| current.replace(Some(Rc::clone(&state))));
        Some(Self { state, previous })
    }

    pub fn messages(&self, messages: impl IntoIterator<Item = ([u8; 32], u64)>) {
        self.state.borrow_mut().messages.extend(messages);
    }

    pub fn unfinished_reason(&self, reason: &'static str) {
        self.state.borrow_mut().drop_reason = reason;
    }

    pub fn take_completion(&self) -> Option<Completion> {
        let mut state = self.state.borrow_mut();
        Some(Completion {
            record: Some(state.pending.take()?),
            mode: state.mode,
            operation: state.last.clone(),
        })
    }

    /// Call only after installation in the committee/proposal consumer has succeeded.
    pub fn ready(&self, kind: &'static str) -> Option<Reference> {
        let recorder = global()?;
        let point = recorder.point();
        let mut state = self.state.borrow_mut();
        {
            let mut record = state.pending.take()?;
            record["ready"] = json!(point);
            record["terminal"] = json!(point);
            record["ready_kind"] = json!(kind);
            record["outcome"] = json!("success");
            record["reason"] = json!("none");
            if record["workload"]["kind"] == "merge" {
                record["plan_ready"] = json!(point);
            }
            recorder.emit("pq.operation_completed", &point, state.mode, record);
        }
        state.last.clone()
    }

    pub fn discard(&self, outcome: &'static str, reason: &'static str) {
        let Some(recorder) = global() else { return };
        let point = recorder.point();
        let mut state = self.state.borrow_mut();
        if let Some(mut record) = state.pending.take() {
            record["terminal"] = json!(point);
            record["outcome"] = json!(outcome);
            record["reason"] = json!(reason);
            if record["workload"]["kind"] == "merge" {
                record["plan_ready"] = json!({"missing":"not_reached"});
            }
            recorder.emit("pq.operation_completed", &point, state.mode, record);
        }
    }
}

impl Drop for Plan {
    fn drop(&mut self) {
        // An early return must never turn an uninstalled result into success.
        let reason = self.state.borrow().drop_reason;
        self.discard("cancelled", reason);
        CURRENT.with(|current| {
            current.replace(self.previous.take());
        });
    }
}

/// One invocation of the synchronous leanVM API. All native inputs are now fixed.
pub struct Call {
    state: Rc<RefCell<State>>,
    record: Option<Value>,
    finished: Option<Point>,
}

/// Called after the recursive adapter installs a result in its next-level input vector.
pub fn intermediate_ready() {
    let Some(recorder) = global() else { return };
    CURRENT.with(|current| {
        if let Some(state) = current.borrow().as_ref() {
            let point = recorder.point();
            let mut state = state.borrow_mut();
            if let Some(mut record) = state.pending.take() {
                record["ready"] = json!(point);
                record["terminal"] = json!(point);
                record["ready_kind"] = json!("intermediate");
                record["outcome"] = json!("success");
                record["reason"] = json!("none");
                recorder.emit("pq.operation_completed", &point, state.mode, record);
            }
        }
    });
}

impl Call {
    pub fn starting(&mut self) {
        if let Some(recorder) = global()
            && let Some(record) = &mut self.record
        {
            record["started"] = json!(recorder.point());
        }
    }
    pub fn start(
        input_proofs: usize,
        raw_signatures: usize,
        messages: &[[u8; 32]],
    ) -> Option<Self> {
        let recorder = global()?;
        let state = CURRENT.with(|current| current.borrow().as_ref().cloned())?;
        let point = recorder.point();
        let mut plan = state.borrow_mut();
        if let Some(mut preceding) = plan.pending.take() {
            // This exact result is now available as an input to the next native call.
            preceding["ready"] = json!(point);
            preceding["terminal"] = json!(point);
            preceding["ready_kind"] = json!("intermediate");
            preceding["outcome"] = json!("success");
            preceding["reason"] = json!("none");
            recorder.emit("pq.operation_completed", &point, plan.mode, preceding);
        }
        plan.calls = plan.calls.saturating_add(1);
        let mut workload = plan.workload.clone();
        if workload["kind"] == "merge" {
            workload["input_proofs"] = json!(input_proofs);
            workload["raw_signatures"] = json!(raw_signatures);
            workload["input_messages"] = json!(messages.len());
            let slots = messages
                .iter()
                .filter_map(|message| plan.messages.get(message).copied())
                .collect::<BTreeSet<_>>();
            if !slots.is_empty() {
                workload["vote_slots"] = json!(slots);
            }
            workload["plan"] = json!(plan.plan);
            workload["plan_call_index"] = json!(plan.calls);
            // Calls within a plan are separately admitted, including recursive levels.
            let sequence = serde_json::from_value::<Reference>(workload["sequence"].clone()).ok();
            workload["attempt_index"] =
                json!(sequence.as_ref().and_then(crate::duty::next_attempt)?);
        }
        let operation = recorder.reference();
        plan.last = Some(operation.clone());
        let mut record = json!({"operation": operation, "workload": workload, "queued": point});
        if let Some((duty, revision)) = &plan.duty {
            record["duty"] = json!(duty);
            record["duty_revision"] = json!(revision);
        }
        recorder.emit("pq.operation_admitted", &point, plan.mode, record.clone());
        record["started"] = json!(point);
        record["backend_finished"] = json!({"missing":"not_reached"});
        record["ready"] = json!({"missing":"not_reached"});
        record["timing_scope"] = json!("backend");
        drop(plan);
        Some(Self {
            state,
            record: Some(record),
            finished: None,
        })
    }

    /// Stamp immediately after the native API returns, before conversions/checks.
    pub fn backend_finished(&mut self) {
        if let Some(recorder) = global() {
            let point = recorder.point();
            if let Some(record) = &mut self.record {
                record["backend_finished"] = json!(point);
            }
            self.finished = Some(point);
        }
    }

    pub fn returned(mut self, bytes: usize) {
        if let Some(mut record) = self.record.take() {
            record["output_proof_bytes"] = json!(bytes);
            self.state.borrow_mut().pending = Some(record);
        }
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        let Some(recorder) = global() else { return };
        let Some(mut record) = self.record.take() else {
            return;
        };
        let terminal = recorder.point();
        // This includes native errors and unwinding caught by the backend adapter.
        record["terminal"] = json!(terminal);
        record["outcome"] = json!("failed");
        record["reason"] = json!("backend_error");
        if record["workload"]["kind"] == "merge" {
            record["plan_ready"] = json!({"missing":"not_reached"});
        }
        recorder.emit(
            "pq.operation_completed",
            &terminal,
            self.state.borrow().mode,
            record,
        );
    }
}
