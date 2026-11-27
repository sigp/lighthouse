//! The single proving lane for PQ committee and proposal work.

use super::{
    attestation_preparation::PreparedAttestations,
    measurement::{self, Job},
};
use crate::{BeaconChain, BeaconChainTypes, metrics};
use parking_lot::Mutex;
use pq_prover::Error;
use serde_json::json;
use slot_clock::SlotClock;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use task_executor::ShutdownReason;
use tokio::sync::Notify;
use tracing::{debug, error, warn};
use types::{EthSpec, Slot};

const PROVER_LOST: ShutdownReason =
    ShutdownReason::Failure("PQ prover became unavailable while serving local validators");

pub(super) const INITIAL_DELAY: Duration = Duration::from_secs(8);
pub(super) const SAFETY_MARGIN: Duration = Duration::from_millis(500);
pub(super) const SINGLE_COMMITTEE_ESTIMATE: Duration = Duration::from_secs(2);
pub(super) const MERGE_MULTIPLIER: f64 = 1.6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Work {
    Committee(Slot, u64, u64),
    Initial(Slot),
    Improvement(Slot),
    Fallback(Slot),
}

impl Work {
    pub(super) fn slot(self) -> Slot {
        match self {
            Self::Committee(slot, _, _)
            | Self::Initial(slot)
            | Self::Improvement(slot)
            | Self::Fallback(slot) => slot,
        }
    }
    pub(super) fn reference_slot(self) -> Slot {
        match self {
            Self::Committee(slot, _, _) => slot,
            _ => self.slot().saturating_sub(2u64),
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Committee(..) => "committee",
            Self::Initial(_) => "initial",
            Self::Improvement(_) => "improvement",
            Self::Fallback(_) => "fallback",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Window {
    pub(super) start: Duration,
    pub(super) end: Duration,
}

#[cfg(test)]
pub(super) fn committee_window(start: Duration, attest: Duration, aggregate: Duration) -> Window {
    Window {
        start: start
            .saturating_add(attest)
            .saturating_add(aggregate.saturating_sub(attest) / 2),
        end: start.saturating_add(aggregate),
    }
}

pub(super) fn proposal_window(
    vote_start: Duration,
    target_start: Duration,
    slot_duration: Duration,
) -> (Window, Duration) {
    (
        Window {
            start: vote_start.saturating_add(INITIAL_DELAY),
            end: target_start.saturating_add(slot_duration),
        },
        target_start,
    )
}

pub(crate) fn fallback_deadline(slot_start: Duration, attestation_due: Duration) -> Duration {
    slot_start.saturating_add(attestation_due.mul_f64(0.75))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Attempt {
    work: Work,
    generation: u64,
    input_revision: u64,
    head_revision: u64,
    reservation_revision: u64,
    experiment: Option<u64>,
    round: u64,
    depth: u64,
    cutoff: Duration,
}

impl Attempt {
    pub(super) fn work(self) -> Work {
        self.work
    }

    pub(super) fn experiment(self) -> Option<u64> {
        self.experiment
    }

    pub(super) fn round(self) -> u64 {
        self.round
    }

    pub(super) fn depth(self) -> u64 {
        self.depth
    }

    pub(super) fn cutoff(self) -> Duration {
        self.cutoff
    }
}

struct Committee {
    window: Window,
    generation: u64,
    local: bool,
    experiment: Option<u64>,
    priority: usize,
    attempted: Option<Attempt>,
    revision: u64,
}

struct Proposal<E: EthSpec> {
    window: Window,
    snapshot_forecast: Duration,
    validator: Option<u64>,
    experiment: Option<u64>,
    round: u64,
    depth: u64,
    backend_calls: u64,
    generation: u64,
    ready: Option<Arc<PreparedAttestations<E>>>,
    last_merge: Option<Duration>,
    attempted: Option<Attempt>,
}

pub(super) type CommitteeDuties = BTreeMap<(Slot, u64, u64), Window>;
pub(super) type ProposalDuties = BTreeMap<Slot, (Window, Duration, u64)>;

#[derive(Default)]
struct Schedule<E: EthSpec> {
    committees: BTreeMap<(Slot, u64, u64), Committee>,
    proposals: BTreeMap<Slot, Proposal<E>>,
    snapshots: BTreeMap<Slot, (Duration, Option<Arc<PreparedAttestations<E>>>)>,
    fallbacks: BTreeMap<Slot, Duration>,
    active: Option<Work>,
    active_job: Option<(u64, Option<u64>)>,
    preparing_proposal: bool,
    preparing_committee: bool,
    stopped: bool,
    duties_head_revision: u64,
    measurements_suspended: bool,
    unavailable: bool,
    generation: u64,
    input_revision: u64,
    network_revision: u64,
    head_revision: u64,
    reservation_revision: u64,
}

impl<E: EthSpec> Schedule<E> {
    fn expire(&mut self, now: Duration) {
        let count = self.committees.len() + self.proposals.len();
        self.committees.retain(|(slot, committee, position), duty| {
            if now < duty.window.end {
                true
            } else {
                if duty.local && duty.experiment.is_none() && duty.attempted.is_none() {
                    pq_measurement::duty::complete(
                        &pq_measurement::duty::committee_key(slot.as_u64(), *committee, *position),
                        "missed_deadline",
                        "deadline",
                        true,
                    );
                }
                if duty.attempted.is_none() && duty.priority > 0 {
                    metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
                    debug!(%slot, committee, "PQ committee reservation expired before dispatch");
                }
                false
            }
        });
        self.proposals.retain(|slot, duty| {
            if now < duty.window.end || duty.experiment.is_some() {
                true
            } else {
                if duty.experiment.is_none() && duty.ready.is_none() {
                    pq_measurement::duty::complete(
                        &pq_measurement::duty::proposal_key(slot.as_u64()),
                        "missed_deadline",
                        "deadline",
                        true,
                    );
                }
                if duty.ready.is_none() {
                    metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
                    debug!(%slot, "PQ initial proposal preparation expired without a candidate");
                }
                false
            }
        });
        if self.committees.len() + self.proposals.len() != count {
            self.reservation_revision += 1;
        }
        self.snapshots.retain(|_, (end, _)| now < *end);
        self.fallbacks.retain(|_, end| now < *end);
    }

    fn replace(&mut self, now: Duration, committees: CommitteeDuties, proposals: ProposalDuties) {
        self.expire(now);
        let previous = (self.generation, self.committees.len(), self.proposals.len());
        self.committees.retain(|key, old| {
            if old.local && old.experiment.is_none() && !committees.contains_key(key) {
                pq_measurement::duty::complete(
                    &pq_measurement::duty::committee_key(key.0.as_u64(), key.1, key.2),
                    "cancelled",
                    "reorg",
                    false,
                );
            }
            if old.experiment.is_some() {
                !committees.contains_key(key)
            } else {
                !old.local || committees.contains_key(key)
            }
        });
        self.proposals.retain(|slot, old| {
            if old.experiment.is_none()
                && !proposals
                    .get(slot)
                    .is_some_and(|(_, _, validator)| old.validator == Some(*validator))
            {
                pq_measurement::duty::complete(
                    &pq_measurement::duty::proposal_key(slot.as_u64()),
                    "cancelled",
                    "reorg",
                    false,
                );
            }
            if old.experiment.is_some() {
                !proposals.contains_key(slot)
            } else {
                proposals
                    .get(slot)
                    .is_some_and(|(_, _, validator)| old.validator == Some(*validator))
            }
        });
        for (key, window) in committees {
            if now >= window.end {
                continue;
            }
            if let Some(duty) = self.committees.get_mut(&key) {
                if !duty.local {
                    duty.local = true;
                    self.reservation_revision += 1;
                }
            } else {
                self.generation += 1;
                self.committees.insert(
                    key,
                    Committee {
                        window,
                        generation: self.generation,
                        local: true,
                        experiment: None,
                        priority: 0,
                        attempted: None,
                        revision: 0,
                    },
                );
            }
        }
        for (slot, (window, snapshot_forecast, validator)) in proposals {
            if now < window.end
                && !self.proposals.contains_key(&slot)
                && !self.snapshots.contains_key(&slot)
            {
                self.generation += 1;
                self.proposals.insert(
                    slot,
                    Proposal {
                        window,
                        snapshot_forecast,
                        validator: Some(validator),
                        experiment: None,
                        round: 0,
                        depth: 0,
                        backend_calls: 0,
                        generation: self.generation,
                        ready: None,
                        last_merge: None,
                        attempted: None,
                    },
                );
            }
        }
        if previous != (self.generation, self.committees.len(), self.proposals.len()) {
            self.reservation_revision += 1;
        }
    }

    fn attempt(&self, work: Work) -> Option<Attempt> {
        let (generation, input_revision, experiment, round, depth, cutoff) = match work {
            Work::Committee(slot, committee, position) => {
                let duty = self.committees.get(&(slot, committee, position))?;
                (
                    duty.generation,
                    duty.revision,
                    duty.experiment,
                    0,
                    0,
                    duty.window.start,
                )
            }
            Work::Initial(slot) | Work::Improvement(slot) => {
                let duty = self.proposals.get(&slot)?;
                if (work == Work::Initial(slot)) != duty.ready.is_none() {
                    return None;
                }
                let revision = match work {
                    Work::Initial(_) if duty.experiment.is_some() => 0,
                    Work::Improvement(_) if duty.experiment.is_some() => self.network_revision,
                    _ => self.input_revision,
                };
                (
                    duty.generation,
                    revision,
                    duty.experiment,
                    duty.round.saturating_add(1),
                    duty.depth,
                    duty.window.start,
                )
            }
            Work::Fallback(_) => return None,
        };
        Some(Attempt {
            work,
            generation,
            input_revision,
            experiment,
            round,
            depth,
            cutoff,
            head_revision: self.head_revision,
            reservation_revision: if matches!(work, Work::Improvement(_)) {
                self.reservation_revision
            } else {
                0
            },
        })
    }

    fn due(&self, now: Duration) -> Option<(Duration, Attempt)> {
        let committees =
            self.committees
                .iter()
                .filter_map(|(&(slot, committee, position), duty)| {
                    let attempt = self.attempt(Work::Committee(slot, committee, position))?;
                    (now >= duty.window.start
                        && now < duty.window.end
                        && duty.attempted != Some(attempt))
                    .then_some((
                        duty.window.end,
                        false,
                        std::cmp::Reverse(duty.priority),
                        attempt,
                    ))
                });
        let proposals = self.proposals.iter().filter_map(|(&slot, duty)| {
            let attempt = self.attempt(Work::Initial(slot))?;
            (now >= duty.window.start && duty.attempted != Some(attempt)).then_some((
                duty.window.end,
                true,
                std::cmp::Reverse(0),
                attempt,
            ))
        });
        committees
            .chain(proposals)
            .min_by_key(|(deadline, is_proposal, priority, attempt)| {
                (*deadline, *is_proposal, *priority, attempt.work.slot())
            })
            .map(|(deadline, _, _, attempt)| (deadline, attempt))
    }

    fn estimate(duty: &Proposal<E>) -> Option<Duration> {
        let ready = duty.ready.as_ref()?;
        duty.last_merge
            .map(|elapsed| elapsed.mul_f64(MERGE_MULTIPLIER))
            .or_else(|| ready.single_committee.then_some(SINGLE_COMMITTEE_ESTIMATE))
    }

    fn next_reservation(&self, now: Duration) -> Option<Duration> {
        self.committees
            .values()
            .filter(|duty| duty.local)
            .map(|duty| duty.window.start)
            .chain(
                self.proposals
                    .values()
                    .filter(|duty| duty.ready.is_none())
                    .map(|duty| duty.window.start),
            )
            .filter(|start| *start > now)
            .min()
    }

    fn improvement_fits(&self, now: Duration, slot: Slot) -> bool {
        let Some(duty) = self.proposals.get(&slot) else {
            return false;
        };
        let Some(estimate) = Self::estimate(duty) else {
            return false;
        };
        let reservation = self.next_reservation(now);
        let boundary = reservation
            .unwrap_or(Duration::MAX)
            .min(duty.snapshot_forecast);
        let fits = now.saturating_add(estimate).saturating_add(SAFETY_MARGIN) <= boundary;
        debug!(%slot, ?estimate, ?reservation, ?boundary, fits, "PQ improvement admission");
        fits
    }

    fn next(&mut self, now: Duration) -> Option<Attempt> {
        self.expire(now);
        if self.stopped
            || self.active.is_some()
            || self.unavailable
            || self.duties_head_revision != self.head_revision
        {
            return None;
        }
        if let Some((_, job)) = self.due(now) {
            return Some(job);
        }
        // An initial reservation with no inputs remains due. Other reserved jobs may proceed.
        if self
            .proposals
            .values()
            .any(|duty| duty.ready.is_none() && duty.window.start <= now && now < duty.window.end)
        {
            return None;
        }
        self.proposals.iter().find_map(|(&slot, duty)| {
            let job = self.attempt(Work::Improvement(slot))?;
            let standalone = duty.ready.as_ref().is_some_and(|ready| ready.standalone)
                && duty.last_merge.is_none()
                && now < duty.snapshot_forecast;
            (duty.attempted != Some(job) && (standalone || self.improvement_fits(now, slot)))
                .then_some(job)
        })
    }

    fn mark_attempt(&mut self, job: Attempt) {
        match job.work {
            Work::Committee(slot, committee, position) => {
                if let Some(duty) = self.committees.get_mut(&(slot, committee, position)) {
                    duty.attempted = Some(job);
                }
            }
            Work::Initial(slot) | Work::Improvement(slot) => {
                if let Some(duty) = self.proposals.get_mut(&slot) {
                    duty.attempted = Some(job);
                }
            }
            Work::Fallback(_) => {}
        }
    }

    fn next_wake(&self, now: Duration) -> Option<Duration> {
        self.committees
            .values()
            .map(|duty| duty.window)
            .chain(self.proposals.values().map(|duty| duty.window))
            .flat_map(|window| [window.start, window.end])
            .filter(|time| *time > now)
            .min()
    }
}

#[derive(Default)]
pub(crate) struct ProverScheduler<E: EthSpec> {
    schedule: Mutex<Schedule<E>>,
    changed: Notify,
}

impl<E: EthSpec> ProverScheduler<E> {
    pub(super) fn replace(
        &self,
        now: Duration,
        committees: CommitteeDuties,
        proposals: ProposalDuties,
        head_revision: u64,
    ) {
        let mut schedule = self.schedule.lock();
        if schedule.head_revision == head_revision {
            schedule.replace(now, committees, proposals);
            schedule.duties_head_revision = head_revision;
            self.changed.notify_one();
        }
    }

    pub(crate) fn head_revision(&self) -> u64 {
        self.schedule.lock().head_revision
    }

    pub(super) fn local_registrations_changed(&self) {
        self.changed.notify_one();
    }

    fn is_unavailable(&self) -> bool {
        self.schedule.lock().unavailable
    }

    pub(crate) fn head_changed(&self) {
        self.schedule.lock().head_revision += 1;
        self.changed.notify_one();
    }

    pub(crate) fn aggregate_changed(&self) {
        self.schedule.lock().input_revision += 1;
        self.changed.notify_one();
    }

    pub(crate) fn measurement_aggregate_changed(&self) {
        self.schedule.lock().network_revision += 1;
        self.changed.notify_one();
    }

    pub(super) fn accept_committee_input(
        &self,
        now: Duration,
        slot: Slot,
        committee: u64,
        debug_window: Option<Window>,
    ) -> bool {
        let mut schedule = self.schedule.lock();
        let key = (slot, committee, 0);
        if let Some(window) = debug_window
            && now < window.start
            && !schedule.committees.contains_key(&key)
        {
            schedule.generation += 1;
            let generation = schedule.generation;
            schedule.committees.insert(
                key,
                Committee {
                    window,
                    generation,
                    local: false,
                    experiment: None,
                    priority: 0,
                    attempted: None,
                    revision: 0,
                },
            );
            self.changed.notify_one();
        }
        schedule
            .committees
            .iter()
            .any(|(&(duty_slot, duty_committee, _), duty)| {
                duty_slot == slot
                    && duty_committee == committee
                    && duty.experiment.is_none()
                    && now < duty.window.start
            })
    }

    pub(super) fn committee_changed(
        &self,
        now: Duration,
        slot: Slot,
        committee: u64,
        priority: usize,
    ) {
        for (&(duty_slot, duty_committee, _), duty) in self.schedule.lock().committees.iter_mut() {
            if duty_slot == slot
                && duty_committee == committee
                && duty.attempted.is_none()
                && now < duty.window.start
            {
                duty.revision += 1;
                duty.priority = priority;
            }
        }
        self.changed.notify_one();
    }

    #[cfg(test)]
    pub(super) fn next(&self, now: Duration) -> Option<Attempt> {
        self.schedule.lock().next(now)
    }

    fn next_task(&self, now: Duration) -> Option<Attempt> {
        let mut schedule = self.schedule.lock();
        let job = schedule.next(now)?;
        let preparing = match job.work {
            Work::Committee(..) => &mut schedule.preparing_committee,
            Work::Initial(_) | Work::Improvement(_) => &mut schedule.preparing_proposal,
            Work::Fallback(_) => return None,
        };
        if *preparing {
            return None;
        }
        *preparing = true;
        Some(job)
    }

    fn task_finished(&self, job: Attempt) {
        let mut schedule = self.schedule.lock();
        match job.work {
            Work::Committee(..) => schedule.preparing_committee = false,
            Work::Initial(_) | Work::Improvement(_) => schedule.preparing_proposal = false,
            Work::Fallback(_) => {}
        }
        self.changed.notify_one();
    }

    pub(super) async fn wait(&self, now: Duration) {
        let next = self.schedule.lock().next_wake(now);
        if let Some(next) = next {
            tokio::select! {
                _ = self.changed.notified() => {},
                _ = tokio::time::sleep(next.saturating_sub(now)) => {},
            }
        } else {
            self.changed.notified().await;
        }
    }

    pub(super) fn ready(&self, job: Attempt) -> Option<Arc<PreparedAttestations<E>>> {
        self.schedule
            .lock()
            .proposals
            .get(&job.work.slot())
            .filter(|duty| duty.generation == job.generation)
            .and_then(|duty| duty.ready.clone())
    }

    pub(crate) fn snapshot(
        &self,
        slot: Slot,
        now: Duration,
        start: Duration,
        slot_duration: Duration,
    ) -> Option<Arc<PreparedAttestations<E>>> {
        let mut schedule = self.schedule.lock();
        schedule.expire(now);
        let expires = start.saturating_add(slot_duration);
        if now >= expires || start > now.saturating_add(slot_duration) {
            return None;
        }
        if let Some((_, ready)) = schedule.snapshots.get(&slot) {
            return ready.clone();
        }
        let ready = if schedule
            .proposals
            .get(&slot)
            .is_some_and(|duty| duty.experiment.is_some())
        {
            None
        } else {
            schedule.proposals.remove(&slot).and_then(|duty| {
                if duty.ready.is_none() {
                    metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
                    warn!(%slot, "PQ proposal reached its snapshot without a prepared proof");
                }
                duty.ready
            })
        };
        schedule.snapshots.insert(slot, (expires, ready.clone()));
        schedule.reservation_revision += 1;
        debug!(%slot, ready = ready.is_some(), active = ?schedule.active, "PQ proposal took its preparation snapshot");
        self.changed.notify_one();
        ready
    }

    pub(super) fn skip(&self, job: Attempt) {
        let mut schedule = self.schedule.lock();
        if schedule.attempt(job.work) == Some(job) {
            schedule.mark_attempt(job);
            if matches!(job.work, Work::Committee(..)) {
                schedule.reservation_revision += 1;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn save(
        &self,
        now: Duration,
        job: Attempt,
        checked_head: u64,
        ready: Arc<PreparedAttestations<E>>,
    ) {
        self.save_candidate(|| Some(now), job, checked_head, ready, true);
    }

    pub(super) fn save_candidate(
        &self,
        clock: impl FnOnce() -> Option<Duration>,
        job: Attempt,
        checked_head: u64,
        ready: Arc<PreparedAttestations<E>>,
        merged: bool,
    ) -> Option<Duration> {
        let mut schedule = self.schedule.lock();
        let now = clock()?;
        schedule.expire(now);
        if schedule.stopped || schedule.head_revision != checked_head {
            return None;
        }
        let slot = job.work.slot();
        let duty = schedule.proposals.get_mut(&slot)?;
        if duty.generation != job.generation || now >= duty.window.end {
            return None;
        }
        debug!(%slot, participation = ready.participation, records = ready.attestations.len(), "Saved PQ proposal proof");
        duty.ready = Some(ready);
        // A better single-child replacement does not consume an improvement round.
        if merged || duty.round == 0 {
            duty.round = job.round;
        }
        duty.depth = job.depth.saturating_add(u64::from(merged));
        duty.attempted = None;
        self.changed.notify_one();
        Some(now)
    }

    pub(super) fn register_measurement(
        &self,
        id: u64,
        now: Duration,
        committee: Option<((Slot, u64), Window)>,
        proposal: Option<(Slot, Window)>,
    ) -> bool {
        let mut schedule = self.schedule.lock();
        if schedule.stopped
            || schedule.unavailable
            || schedule.measurements_suspended
            || committee.is_some_and(|(key, window)| {
                now >= window.start || schedule.committees.contains_key(&(key.0, key.1, 0))
            })
            || proposal.is_some_and(|(slot, window)| {
                now >= window.start
                    || schedule.proposals.contains_key(&slot)
                    || schedule.snapshots.contains_key(&slot)
            })
        {
            return false;
        }
        schedule.generation += 1;
        let generation = schedule.generation;
        if let Some((key, window)) = committee {
            schedule.committees.insert(
                (key.0, key.1, 0),
                Committee {
                    window,
                    generation,
                    local: true,
                    experiment: Some(id),
                    priority: 0,
                    attempted: None,
                    revision: 0,
                },
            );
        }
        if let Some((slot, window)) = proposal {
            schedule.proposals.insert(
                slot,
                Proposal {
                    window,
                    snapshot_forecast: window.end,
                    validator: None,
                    experiment: Some(id),
                    generation,
                    round: 0,
                    depth: 0,
                    backend_calls: 0,
                    ready: None,
                    last_merge: None,
                    attempted: None,
                },
            );
        }
        schedule.reservation_revision += 1;
        self.changed.notify_one();
        true
    }

    pub(super) fn measurement_committee_changed(
        &self,
        slot: Slot,
        committee: u64,
        priority: usize,
    ) {
        if let Some(duty) = self
            .schedule
            .lock()
            .committees
            .get_mut(&(slot, committee, 0))
            && duty.experiment.is_some()
        {
            duty.revision += 1;
            duty.priority = priority;
            self.changed.notify_one();
        }
    }

    pub(super) fn withdraw_measurements(&self) {
        self.remove_measurements(false);
    }

    pub(super) fn suspend_measurements(&self) {
        self.remove_measurements(true);
    }

    fn remove_measurements(&self, suspend: bool) {
        let mut schedule = self.schedule.lock();
        schedule.measurements_suspended |= suspend;
        let previous = schedule.committees.len() + schedule.proposals.len();
        schedule
            .committees
            .retain(|_, duty| duty.experiment.is_none());
        schedule
            .proposals
            .retain(|_, duty| duty.experiment.is_none());
        if previous != schedule.committees.len() + schedule.proposals.len() {
            schedule.reservation_revision += 1;
            self.changed.notify_one();
        }
    }

    pub(super) fn measurement_snapshot(
        &self,
        slot: Slot,
        id: u64,
        now: Duration,
    ) -> (
        Option<Arc<PreparedAttestations<E>>>,
        u64,
        u64,
        u64,
        Option<(u64, Option<u64>)>,
    ) {
        let mut schedule = self.schedule.lock();
        let active = schedule.active_job;
        if !schedule
            .proposals
            .get(&slot)
            .is_some_and(|duty| duty.experiment == Some(id) && now >= duty.window.end)
        {
            return (None, 0, 0, 0, active);
        }
        let ready = schedule.proposals.remove(&slot);
        schedule.reservation_revision += 1;
        self.changed.notify_one();
        ready.map_or((None, 0, 0, 0, active), |duty| {
            (
                duty.ready,
                duty.round,
                duty.depth,
                duty.backend_calls,
                active,
            )
        })
    }

    pub(crate) fn active_job(&self) -> Option<(u64, Option<u64>)> {
        self.schedule.lock().active_job
    }

    pub(super) fn is_ready_for_observation(&self) -> bool {
        !self.is_unavailable()
    }

    pub(super) fn start(self: &Arc<Self>, now: Duration, job: Attempt) -> Option<Active<E>> {
        let mut schedule = self.schedule.lock();
        let next = schedule.next(now)?;
        // New aggregates do not invalidate a checked proposal batch. Use the latest
        // schedule for priority and admission, and the original revision for retry.
        if next.work != job.work
            || next.generation != job.generation
            || next.head_revision != job.head_revision
            || (matches!(job.work, Work::Committee(..))
                && next.input_revision != job.input_revision)
        {
            return None;
        }
        if let Work::Improvement(slot) = job.work
            && !schedule.improvement_fits(now, slot)
        {
            return None;
        }
        let reserved_start = match job.work {
            Work::Committee(slot, committee, position) => schedule
                .committees
                .get(&(slot, committee, position))
                .map(|duty| duty.window.start),
            Work::Initial(slot) => schedule.proposals.get(&slot).map(|duty| duty.window.start),
            _ => None,
        };
        let reserve_delay = reserved_start.map(|start| now.saturating_sub(start));
        let next_reservation = schedule.next_reservation(now);
        let deadline = match job.work {
            Work::Committee(slot, committee, position) => schedule
                .committees
                .get(&(slot, committee, position))
                .map(|duty| duty.window.end),
            Work::Initial(slot) | Work::Improvement(slot) => schedule
                .proposals
                .get(&slot)
                .map(|duty| duty.snapshot_forecast),
            Work::Fallback(_) => None,
        };
        let estimate = if let Work::Improvement(slot) = job.work {
            schedule.proposals.get(&slot).and_then(Schedule::estimate)
        } else {
            None
        };
        if matches!(job.work, Work::Initial(_) | Work::Improvement(_))
            && let Some(duty) = schedule.proposals.get_mut(&job.work.slot())
        {
            duty.backend_calls = duty.backend_calls.saturating_add(1);
        }
        schedule.active = Some(job.work);
        schedule.mark_attempt(job);
        debug!(work = ?job.work, ?reserve_delay, "Starting scheduled PQ proving work");
        Some(Active {
            scheduler: Arc::clone(self),
            work: job.work,
            generation: Some(job.generation),
            next_reservation,
            deadline,
            estimate,
            completed: false,
        })
    }

    pub(crate) fn start_fallback(
        self: &Arc<Self>,
        now: Duration,
        slot: Slot,
        deadline: Duration,
    ) -> Option<Active<E>> {
        let mut schedule = self.schedule.lock();
        schedule.expire(now);
        if schedule.stopped
            || now >= deadline
            || schedule.active.is_some()
            || schedule.unavailable
            || schedule.fallbacks.contains_key(&slot)
            || schedule.due(now).is_some_and(|(end, _)| end < deadline)
        {
            return None;
        }
        let work = Work::Fallback(slot);
        schedule.active = Some(work);
        schedule.fallbacks.insert(slot, deadline);
        debug!(%slot, "Starting PQ proposal fallback proof");
        Some(Active {
            scheduler: Arc::clone(self),
            work,
            generation: None,
            next_reservation: schedule.next_reservation(now),
            deadline: Some(deadline),
            estimate: None,
            completed: false,
        })
    }

    pub(super) fn committee_result_is_current(&self, now: Duration, job: Attempt) -> bool {
        let Work::Committee(slot, committee, position) = job.work else {
            return false;
        };
        let schedule = self.schedule.lock();
        schedule.head_revision == job.head_revision
            && schedule
                .committees
                .get(&(slot, committee, position))
                .is_some_and(|duty| duty.generation == job.generation && now < duty.window.end)
    }

    pub(super) fn improvement_can_merge(&self, now: Duration, job: Attempt) -> bool {
        match job.work {
            Work::Improvement(slot) => self.schedule.lock().improvement_fits(now, slot),
            _ => false,
        }
    }
}

// Cancelling the async driver closes the schedule, while the owned RPC still runs to completion.
struct Driver<E: EthSpec>(Arc<ProverScheduler<E>>);

impl<E: EthSpec> Drop for Driver<E> {
    fn drop(&mut self) {
        self.0.schedule.lock().stopped = true;
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn start_pq_aggregation(self: &Arc<Self>) {
        if !self.spec.is_pq_scheduled() || self.pq_provers.is_none() {
            return;
        }
        self.start_pq_duty_updates();
        let chain = Arc::clone(self);
        self.task_executor.spawn(async move {
            let Some(provers) = &chain.pq_provers else { return; };
            let scheduler = Driver(Arc::clone(&provers.scheduler));
            loop {
                if scheduler.0.is_unavailable() && chain.has_pq_local_validators().await {
                    error!(reason = PROVER_LOST.message(), "Shutting down beacon node");
                    if let Err(error) = chain.shutdown_sender().try_send(PROVER_LOST) {
                        error!(?error, "Unable to send PQ prover shutdown signal");
                    }
                    return;
                }

                let Some(now) = chain.slot_clock.now_duration() else { return; };
                let Some(job) = scheduler.0.next_task(now) else {
                    scheduler.0.wait(now).await;
                    continue;
                };
                let owner = Arc::clone(&chain);
                let worker_scheduler = Arc::clone(&scheduler.0);
                let trace = chain.pq_measurement.job(job, now);
                chain.task_executor.spawn_blocking(move || {
                    let result = match job.work() {
                        Work::Committee(slot, committee, position) => owner.prove_pq_committee(job, slot, committee, position, &trace),
                        Work::Initial(slot) | Work::Improvement(slot) => owner.prepare_pq_attestations_with_trace(job, slot, &trace),
                        Work::Fallback(_) => Ok(()),
                    };
                    if let Err(error) = result {
                        trace.emit("job_outcome", "failed", owner.slot_clock.now_duration().unwrap_or(now), || json!({}));
                        worker_scheduler.skip(job);
                        debug!(work = ?job.work(), ?error, "Unable to finish PQ proving job");
                    }
                    worker_scheduler.task_finished(job);
                }, "pq_prover_job");
            }
        }, "pq_prover_scheduler");
    }
}

/// Moved into the blocking RPC closure. Dropping an observer never drops this token.
pub(crate) struct Active<E: EthSpec> {
    scheduler: Arc<ProverScheduler<E>>,
    work: Work,
    generation: Option<u64>,
    next_reservation: Option<Duration>,
    deadline: Option<Duration>,
    estimate: Option<Duration>,
    completed: bool,
}

impl<E: EthSpec> Active<E> {
    #[cfg(test)]
    pub(crate) fn run(
        self,
        backend: impl FnOnce() -> Result<pq_prover::Proof, Error>,
    ) -> Result<pq_prover::Proof, Error> {
        let started = Instant::now();
        let result = backend();
        self.complete(&result, started.elapsed());
        result
    }

    pub(crate) fn run_observed(
        self,
        job: &Job<E>,
        experiment: Option<u64>,
        clock: impl Fn() -> Option<Duration>,
        backend: impl FnOnce() -> Result<pq_prover::Proof, Error>,
    ) -> Result<pq_prover::Proof, Error> {
        let backend_calls = {
            let mut schedule = self.scheduler.schedule.lock();
            schedule.active_job = Some((job.id, experiment));
            schedule
                .proposals
                .get(&self.work.slot())
                .map(|duty| duty.backend_calls)
        };
        let started_wall = clock().unwrap_or_default();
        let wait = job.queue_wait();
        job.latency("queue", wait);
        job.emit("proof_started", "started", started_wall, || {
            json!({
                "queue_wait_ns": measurement::ns(wait),
            "backend_call_count": backend_calls,
                "estimated_ns": self.estimate.map(measurement::ns),
                "next_reservation_wall_ns": self.next_reservation.map(measurement::ns),
                "useful_deadline_wall_ns": self.deadline.map(measurement::ns),
                "margin_ns": measurement::ns(SAFETY_MARGIN),
            })
        });
        let started = Instant::now();
        let result = backend();
        let elapsed = started.elapsed();
        let finished = clock().unwrap_or(started_wall.saturating_add(elapsed));
        let deadline = self.deadline;
        self.complete(&result, elapsed);
        job.latency("backend", elapsed);
        job.emit("proof_finished", if result.is_ok() { "success" } else { "failed" }, finished, || json!({
            "backend_duration_ns": measurement::ns(elapsed),
            "late": deadline.is_some_and(|end| finished >= end),
            "proof_bytes": result.as_ref().ok().map(pq_prover::Proof::len),
            "proof_id": result.as_ref().ok().map(|proof| measurement::proof_id(proof.as_bytes())),
        }));
        result
    }

    fn complete(mut self, result: &Result<pq_prover::Proof, Error>, elapsed: Duration) {
        let uncertain = matches!(result, Err(Error::BackendPanicked));
        let mut schedule = self.scheduler.schedule.lock();
        schedule.active = None;
        schedule.active_job = None;
        if matches!(self.work, Work::Committee(..)) {
            schedule.reservation_revision += 1;
        }
        schedule.unavailable |= uncertain;
        let measured_merge = matches!(
            result,
            Ok(_) | Err(Error::ProvingFailed(_) | Error::ClaimsMismatch { .. })
        );
        if measured_merge
            && matches!(self.work, Work::Initial(_) | Work::Improvement(_))
            && let Some(duty) = schedule.proposals.get_mut(&self.work.slot())
            && Some(duty.generation) == self.generation
        {
            duty.last_merge = Some(elapsed);
        }
        debug!(work = ?self.work, ?elapsed, uncertain, "PQ backend request returned");
        if uncertain {
            warn!("PQ proving lane is unavailable after an internal leanVM failure");
        }
        self.completed = true;
        self.scheduler.changed.notify_one();
    }
}

impl<E: EthSpec> Drop for Active<E> {
    fn drop(&mut self) {
        if !self.completed {
            let mut schedule = self.scheduler.schedule.lock();
            schedule.active = None;
            schedule.active_job = None;
            schedule.unavailable = true;
            warn!("PQ proving operation exited without a completion");
            self.scheduler.changed.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_prover::Proof;
    use types::MinimalEthSpec;

    type Scheduler = ProverScheduler<MinimalEthSpec>;
    const TARGET: Slot = Slot::new(2);

    fn seconds(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn proposal() -> ProposalDuties {
        let (window, forecast) = proposal_window(Duration::ZERO, seconds(24), seconds(12));
        BTreeMap::from([(TARGET, (window, forecast, 0))])
    }

    fn committee(committee: u64) -> CommitteeDuties {
        let window = committee_window(seconds(12), seconds(3), seconds(6));
        BTreeMap::from([((Slot::new(1), committee, 0), window)])
    }

    fn candidate(
        single_committee: bool,
        participation: u64,
    ) -> Arc<PreparedAttestations<MinimalEthSpec>> {
        Arc::new(PreparedAttestations {
            attestations: vec![],
            statements: vec![],
            proof: Default::default(),
            participation,
            single_committee,
            standalone: true,
        })
    }

    #[test]
    fn measurement_respects_reservation_and_snapshot_boundary() {
        let scheduler = Arc::new(Scheduler::default());
        let committee_slot = Slot::new(1);
        let window = committee_window(seconds(12), seconds(3), seconds(6));
        let proposal = Window {
            start: seconds(8),
            end: seconds(24),
        };
        assert!(scheduler.register_measurement(
            0,
            seconds(1),
            Some(((committee_slot, 0), window)),
            Some((TARGET, proposal))
        ));
        scheduler.replace(seconds(2), BTreeMap::new(), BTreeMap::new(), 0);
        let initial = scheduler.next(seconds(8)).unwrap();
        assert_eq!(initial.experiment(), Some(0));
        assert_eq!(initial.round(), 1);
        scheduler
            .save_candidate(|| Some(seconds(8)), initial, 0, candidate(true, 1), false)
            .unwrap();

        let boundary = seconds(14);
        let improve = scheduler.next(boundary).unwrap();
        assert_eq!(improve.round(), 2);
        assert_eq!(improve.depth(), 0);
        assert!(
            scheduler
                .start(boundary + Duration::from_millis(1), improve)
                .is_none()
        );

        let deadline = seconds(24);
        assert!(
            scheduler
                .save_candidate(|| Some(deadline), improve, 0, candidate(true, 2), true)
                .is_none()
        );
        let (ready, round, depth, calls, _) = scheduler.measurement_snapshot(TARGET, 0, deadline);
        assert_eq!(ready.unwrap().participation, 1);
        assert_eq!((round, depth, calls), (1, 0, 0));
        assert!(scheduler.next(deadline).is_none());
    }

    #[test]
    fn staggered_local_positions_have_separate_reservations() {
        let scheduler = Arc::new(Scheduler::default());
        let slot = Slot::new(1);
        scheduler.replace(
            seconds(12),
            BTreeMap::from([
                (
                    (slot, 0, 0),
                    Window {
                        start: Duration::from_millis(16_800),
                        end: Duration::from_millis(19_200),
                    },
                ),
                (
                    (slot, 0, 1),
                    Window {
                        start: Duration::from_millis(17_400),
                        end: Duration::from_millis(19_800),
                    },
                ),
            ]),
            BTreeMap::new(),
            0,
        );
        scheduler.committee_changed(seconds(16), slot, 0, 1);
        let first = scheduler.next(Duration::from_millis(16_800)).unwrap();
        assert_eq!(first.work(), Work::Committee(slot, 0, 0));
        let active = scheduler
            .start(Duration::from_millis(16_800), first)
            .unwrap();
        assert!(scheduler.accept_committee_input(Duration::from_millis(17_000), slot, 0, None));
        scheduler.committee_changed(Duration::from_millis(17_000), slot, 0, 2);
        active.complete(&Ok(Proof::default()), Duration::from_millis(100));
        assert!(scheduler.next(Duration::from_millis(17_000)).is_none());
        let second = scheduler.next(Duration::from_millis(17_400)).unwrap();
        assert_eq!(second.work(), Work::Committee(slot, 0, 1));
        assert!(!scheduler.accept_committee_input(Duration::from_millis(17_400), slot, 0, None));
        assert_eq!(first.cutoff(), Duration::from_millis(16_800));
        assert_eq!(second.cutoff(), Duration::from_millis(17_400));
    }

    #[test]
    fn early_prover_schedules_initial_work_and_protects_known_reservations() {
        let scheduler = Arc::new(Scheduler::default());
        scheduler.replace(seconds(1), committee(0), proposal(), 0);
        assert!(scheduler.next(seconds(7)).is_none());
        let initial = scheduler.next(seconds(8)).unwrap();
        assert_eq!(initial.work(), Work::Initial(TARGET));
        let active = scheduler.start(seconds(8), initial).unwrap();
        active.complete(&Ok(Proof::default()), seconds(1));
        scheduler.save(seconds(8), initial, 0, candidate(true, 1));

        // Five measured seconds predict eight. The committee reserves 16.5.
        scheduler
            .schedule
            .lock()
            .proposals
            .get_mut(&TARGET)
            .unwrap()
            .last_merge = Some(seconds(5));
        let at_boundary = scheduler.next(seconds(8)).unwrap();
        assert_eq!(at_boundary.work(), Work::Improvement(TARGET));
        assert!(
            scheduler
                .start(seconds(8) + Duration::from_millis(1), at_boundary)
                .is_none()
        );

        let due = Duration::from_millis(16_500);
        let job = scheduler.next(due).unwrap();
        assert_eq!(job.work(), Work::Committee(Slot::new(1), 0, 0));
        let active = scheduler.start(due, job).unwrap();
        assert!(scheduler.next(seconds(18)).is_none());
        active.complete(&Ok(Proof::default()), seconds(1));

        scheduler
            .schedule
            .lock()
            .proposals
            .get_mut(&TARGET)
            .unwrap()
            .last_merge = Some(seconds(1));
        assert_eq!(
            scheduler.next(seconds(18)).unwrap().work(),
            Work::Improvement(TARGET)
        );
    }

    #[test]
    fn early_prover_dispatches_proposal_despite_new_aggregates() {
        let scheduler = Arc::new(Scheduler::default());
        scheduler.replace(seconds(1), committee(0), proposal(), 0);
        let initial = scheduler.next(seconds(8)).unwrap();
        scheduler.aggregate_changed();
        let active = scheduler.start(seconds(8), initial).unwrap();
        active.complete(&Ok(Proof::default()), seconds(1));
        scheduler.save(seconds(9), initial, 0, candidate(true, 1));

        let improvement = scheduler.next(seconds(9)).unwrap();
        scheduler.aggregate_changed();
        let active = scheduler.start(seconds(9), improvement).unwrap();
        let rejected = Err(Error::ProvingFailed("test failure".into()));
        active.complete(&rejected, seconds(4));
        let duty = scheduler.schedule.lock();
        assert_eq!(
            duty.proposals.get(&TARGET).unwrap().last_merge,
            Some(seconds(4))
        );
    }

    #[test]
    fn early_prover_refreshes_duties_and_drops_expired_or_withdrawn_jobs() {
        let scheduler = Arc::new(Scheduler::default());
        scheduler.replace(seconds(1), committee(0), proposal(), 0);
        let initial = scheduler.next(seconds(8)).unwrap();
        scheduler.skip(initial);
        assert!(
            scheduler.next(seconds(10)).is_none(),
            "wait for a changed input"
        );
        scheduler.aggregate_changed();
        assert_eq!(
            scheduler.next(seconds(10)).unwrap().work(),
            Work::Initial(TARGET)
        );

        let cutoff = Duration::from_millis(16_500);
        let old = scheduler.next(cutoff).unwrap();
        assert_eq!(old.work(), Work::Committee(Slot::new(1), 0, 0));
        assert!(scheduler.committee_result_is_current(cutoff, old));
        scheduler.head_changed();
        assert!(!scheduler.committee_result_is_current(cutoff, old));
        assert!(scheduler.start(cutoff, old).is_none());
        scheduler.replace(seconds(17), committee(0), proposal(), 0);
        assert!(
            scheduler.next(seconds(17)).is_none(),
            "reject stale head refresh"
        );
        scheduler.replace(seconds(17), committee(1), proposal(), 1);
        let current = scheduler.next(seconds(17)).unwrap();
        assert_eq!(current.work(), Work::Committee(Slot::new(1), 1, 0));
        assert!(scheduler.start(seconds(17), old).is_none());
        assert!(scheduler.start(seconds(18), current).is_none());
        assert!(scheduler.schedule.lock().committees.is_empty());
    }

    #[test]
    fn early_prover_uses_single_committee_estimate_and_reconsiders_after_reservation() {
        for single_committee in [false, true] {
            let scheduler = Arc::new(Scheduler::default());
            scheduler.replace(seconds(1), committee(0), proposal(), 0);
            let initial = scheduler.next(seconds(8)).unwrap();
            scheduler.save(seconds(8), initial, 0, candidate(single_committee, 1));

            let increase = scheduler.next(seconds(15)).unwrap();
            assert!(scheduler.start(seconds(15), increase).is_none());
            scheduler.skip(increase);
            let due = scheduler.next(Duration::from_millis(16_500)).unwrap();
            let active = scheduler.start(Duration::from_millis(16_500), due).unwrap();
            active.complete(&Ok(Proof::default()), seconds(1));

            let retry = scheduler.next(seconds(17)).unwrap();
            assert_eq!(retry.work(), Work::Improvement(TARGET));
            let observed = scheduler.start(seconds(17), retry);
            assert_eq!(observed.is_some(), single_committee);
            if let Some(active) = observed {
                active.complete(&Ok(Proof::default()), seconds(1));
            }

            if single_committee {
                scheduler.save(seconds(17), retry, 0, candidate(true, 2));
                for round in 3..=5 {
                    let job = scheduler.next(seconds(17)).unwrap();
                    scheduler
                        .start(seconds(17), job)
                        .unwrap()
                        .complete(&Ok(Proof::default()), seconds(1));
                    scheduler.save(seconds(17), job, 0, candidate(true, round));
                }
            }
        }
    }

    #[test]
    fn early_prover_snapshot_is_independent_of_running_improvement() {
        let scheduler = Arc::new(Scheduler::default());
        scheduler.replace(seconds(1), BTreeMap::new(), proposal(), 0);
        let initial = scheduler.next(seconds(8)).unwrap();
        let old = candidate(true, 1);
        scheduler.save(seconds(8), initial, 0, Arc::clone(&old));
        let improvement = scheduler.next(seconds(10)).unwrap();
        let active = scheduler.start(seconds(10), improvement).unwrap();

        let (continue_proof, backend_wait) = std::sync::mpsc::channel();
        let (report, caller) = tokio::sync::oneshot::channel();
        let backend = std::thread::spawn(move || {
            backend_wait.recv().unwrap();
            active.complete(&Ok(Proof::default()), seconds(1));
            let _ = report.send(());
        });

        // A caller disappearing cannot free the proving lane. Publication can take the ready Arc.
        drop(caller);
        let got = scheduler
            .snapshot(TARGET, seconds(24), seconds(24), seconds(12))
            .unwrap();
        assert!(Arc::ptr_eq(&got, &old));
        assert!(
            scheduler
                .start_fallback(seconds(24), TARGET, seconds(26))
                .is_none()
        );
        continue_proof.send(()).unwrap();
        backend.join().unwrap();

        scheduler.save(seconds(24), improvement, 0, candidate(true, 2));
        let retry = scheduler
            .snapshot(TARGET, seconds(25), seconds(24), seconds(12))
            .unwrap();
        assert!(Arc::ptr_eq(&retry, &old));
        assert!(
            scheduler
                .start_fallback(seconds(25), TARGET, seconds(26))
                .is_some()
        );
    }

    #[cfg(all(feature = "spec-minimal", not(debug_assertions)))]
    #[tokio::test]
    async fn early_prover_registered_shutdown_depends_on_local_interest() {
        use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
        use eth2::types::ProposerPreparationData;
        use types::{Address, Epoch, ForkName, RelativeEpoch};

        type E = MinimalEthSpec;
        type Harness = BeaconChainHarness<EphemeralHarnessType<E>>;

        async fn shutdown(harness: &Harness) -> ShutdownReason {
            loop {
                if let Some(reason) = harness.shutdown_reasons().into_iter().next() {
                    return reason;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        for register_proposer_first in [true, false] {
            let spec = Arc::new(ForkName::Pq.make_genesis_spec(E::default_spec()));
            let harness = Harness::builder(E::default())
                .spec(spec)
                .deterministic_keypairs(E::slots_per_epoch() as usize)
                .fresh_ephemeral_store()
                .mock_execution_layer()
                .build();
            let chain = &harness.chain;
            let scheduler = &chain.pq_provers.as_ref().unwrap().scheduler;
            let now = chain.slot_clock.now_duration().unwrap();

            if register_proposer_first {
                let registration = ProposerPreparationData {
                    validator_index: 0,
                    fee_recipient: Address::ZERO,
                };
                chain
                    .execution_layer
                    .as_ref()
                    .unwrap()
                    .update_proposer_preparation(Epoch::new(0), [(&registration, &None)])
                    .await;
            }
            chain.start_pq_aggregation();

            assert!(scheduler.start_fallback(now, Slot::new(0), now).is_none());
            let normal = scheduler
                .start_fallback(now, Slot::new(0), now + seconds(1))
                .unwrap();
            assert!(matches!(
                normal.run(|| Err(Error::InvalidInput("known completion".into()))),
                Err(Error::InvalidInput(_)),
            ));
            assert!(!scheduler.is_unavailable());
            assert!(harness.shutdown_reasons().is_empty());

            let failed = scheduler
                .start_fallback(now, Slot::new(1), now + seconds(1))
                .unwrap();
            assert!(matches!(
                failed.run(|| Err(Error::BackendPanicked)),
                Err(Error::BackendPanicked),
            ));
            assert!(scheduler.is_unavailable());
            assert!(
                scheduler
                    .start_fallback(now, Slot::new(2), now + seconds(1))
                    .is_none()
            );

            if !register_proposer_first {
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), shutdown(&harness))
                        .await
                        .is_err(),
                    "an observer must stay up after the proving lane fails"
                );
                let state = harness.get_current_state();
                let duty = state
                    .get_attestation_duties(0, RelativeEpoch::Current)
                    .unwrap()
                    .unwrap();
                chain.register_pq_aggregation_duty(duty.slot, duty.index, 0);
            }

            assert_eq!(
                tokio::time::timeout(seconds(2), shutdown(&harness))
                    .await
                    .unwrap(),
                PROVER_LOST,
            );
            assert!(harness.shutdown_reasons().is_empty());
        }
    }

    #[test]
    fn early_prover_fails_closed_after_ambiguous_transport_error() {
        let scheduler = Arc::new(Scheduler::default());
        scheduler.replace(seconds(1), BTreeMap::new(), proposal(), 0);
        let job = scheduler.next(seconds(8)).unwrap();
        let active = scheduler.start(seconds(8), job).unwrap();
        active.complete(&Err(Error::BackendPanicked), seconds(1));
        assert!(
            scheduler
                .start_fallback(seconds(24), TARGET, seconds(26))
                .is_none()
        );
    }
}
