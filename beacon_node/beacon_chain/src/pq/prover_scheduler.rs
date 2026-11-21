//! The single proving lane for PQ committee and proposal work.

use super::attestation_preparation::PreparedAttestations;
use crate::{BeaconChain, BeaconChainTypes, metrics};
use parking_lot::Mutex;
use pq_prover::Error;
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

const INITIAL_DELAY: Duration = Duration::from_secs(8);
const SAFETY_MARGIN: Duration = Duration::from_millis(500);
const SINGLE_COMMITTEE_ESTIMATE: Duration = Duration::from_secs(2);
const MERGE_MULTIPLIER: f64 = 1.6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Work {
    Committee(Slot, u64),
    Initial(Slot),
    Improvement(Slot),
    Fallback(Slot),
}

impl Work {
    fn slot(self) -> Slot {
        match self {
            Self::Committee(slot, _)
            | Self::Initial(slot)
            | Self::Improvement(slot)
            | Self::Fallback(slot) => slot,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Window {
    start: Duration,
    end: Duration,
}

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
}

impl Attempt {
    pub(super) fn work(self) -> Work {
        self.work
    }
}

struct Committee {
    window: Window,
    generation: u64,
    local: bool,
    learned_late: bool,
    priority: usize,
    attempted: Option<Attempt>,
    revision: u64,
}

struct Proposal<E: EthSpec> {
    window: Window,
    snapshot_forecast: Duration,
    validator: u64,
    generation: u64,
    ready: Option<Arc<PreparedAttestations<E>>>,
    last_merge: Option<Duration>,
    attempted: Option<Attempt>,
}

pub(super) type CommitteeDuties = BTreeMap<(Slot, u64), Window>;
pub(super) type ProposalDuties = BTreeMap<Slot, (Window, Duration, u64)>;

#[derive(Default)]
struct Schedule<E: EthSpec> {
    committees: BTreeMap<(Slot, u64), Committee>,
    proposals: BTreeMap<Slot, Proposal<E>>,
    snapshots: BTreeMap<Slot, (Duration, Option<Arc<PreparedAttestations<E>>>)>,
    fallbacks: BTreeMap<Slot, Duration>,
    active: Option<Work>,
    preparing_proposal: bool,
    preparing_committee: bool,
    stopped: bool,
    duties_head_revision: u64,
    unavailable: bool,
    generation: u64,
    input_revision: u64,
    head_revision: u64,
    reservation_revision: u64,
}

impl<E: EthSpec> Schedule<E> {
    fn expire(&mut self, now: Duration) {
        let count = self.committees.len() + self.proposals.len();
        self.committees.retain(|(slot, committee), duty| {
            if now < duty.window.end {
                true
            } else {
                if duty.attempted.is_none() && duty.priority > 0 {
                    metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
                    debug!(%slot, committee, "PQ committee reservation expired before dispatch");
                }
                false
            }
        });
        self.proposals.retain(|slot, duty| {
            if now < duty.window.end {
                true
            } else {
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
        self.committees
            .retain(|key, old| !old.local || committees.contains_key(key));
        self.proposals.retain(|slot, old| {
            proposals
                .get(slot)
                .is_some_and(|(_, _, validator)| old.validator == *validator)
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
                        learned_late: now >= window.start,
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
                        validator,
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
        let (generation, input_revision) = match work {
            Work::Committee(slot, committee) => {
                let duty = self.committees.get(&(slot, committee))?;
                (duty.generation, duty.revision)
            }
            Work::Initial(slot) | Work::Improvement(slot) => {
                let duty = self.proposals.get(&slot)?;
                if (work == Work::Initial(slot)) != duty.ready.is_none() {
                    return None;
                }
                (duty.generation, self.input_revision)
            }
            Work::Fallback(_) => return None,
        };
        Some(Attempt {
            work,
            generation,
            input_revision,
            head_revision: self.head_revision,
            reservation_revision: if matches!(work, Work::Improvement(_)) {
                self.reservation_revision
            } else {
                0
            },
        })
    }

    fn due(&self, now: Duration) -> Option<(Duration, Attempt)> {
        let committees = self
            .committees
            .iter()
            .filter_map(|(&(slot, committee), duty)| {
                let attempt = self.attempt(Work::Committee(slot, committee))?;
                (now >= duty.window.start && duty.attempted != Some(attempt)).then_some((
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
            .any(|duty| duty.ready.is_none() && duty.window.start <= now)
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
            Work::Committee(slot, committee) => {
                if let Some(duty) = self.committees.get_mut(&(slot, committee)) {
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

    pub(super) fn head_revision(&self) -> u64 {
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

    pub(super) fn accept_committee_input(
        &self,
        now: Duration,
        slot: Slot,
        committee: u64,
        debug_window: Option<Window>,
    ) -> bool {
        let mut schedule = self.schedule.lock();
        let key = (slot, committee);
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
                    learned_late: false,
                    priority: 0,
                    attempted: None,
                    revision: 0,
                },
            );
            self.changed.notify_one();
        }
        schedule.committees.get(&key).is_some_and(|duty| {
            now < duty.window.end && (now < duty.window.start || duty.learned_late)
        })
    }

    pub(super) fn committee_changed(&self, slot: Slot, committee: u64, priority: usize) {
        if let Some(duty) = self.schedule.lock().committees.get_mut(&(slot, committee)) {
            duty.revision += 1;
            duty.priority = priority;
            self.changed.notify_one();
        }
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
        let ready = schedule.proposals.remove(&slot).and_then(|duty| {
            if duty.ready.is_none() {
                metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
                warn!(%slot, "PQ proposal reached its snapshot without a prepared proof");
            }
            duty.ready
        });
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

    pub(super) fn save(
        &self,
        now: Duration,
        job: Attempt,
        checked_head: u64,
        ready: Arc<PreparedAttestations<E>>,
    ) {
        let mut schedule = self.schedule.lock();
        schedule.expire(now);
        if schedule.stopped || schedule.head_revision != checked_head {
            return;
        }
        let slot = job.work.slot();
        if let Some(duty) = schedule.proposals.get_mut(&slot)
            && duty.generation == job.generation
        {
            debug!(%slot, participation = ready.participation, records = ready.attestations.len(), "Saved PQ proposal proof");
            duty.ready = Some(ready);
            // A newly saved result can expose a different marginal winner.
            duty.attempted = None;
        }
        self.changed.notify_one();
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
            Work::Committee(slot, committee) => schedule
                .committees
                .get(&(slot, committee))
                .map(|duty| duty.window.start),
            Work::Initial(slot) => schedule.proposals.get(&slot).map(|duty| duty.window.start),
            _ => None,
        };
        let reserve_delay = reserved_start.map(|start| now.saturating_sub(start));
        schedule.active = Some(job.work);
        schedule.mark_attempt(job);
        debug!(work = ?job.work, ?reserve_delay, "Starting scheduled PQ proving work");
        Some(Active {
            scheduler: Arc::clone(self),
            work: job.work,
            generation: Some(job.generation),
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
            completed: false,
        })
    }

    pub(super) fn committee_result_is_current(&self, now: Duration, job: Attempt) -> bool {
        let Work::Committee(slot, committee) = job.work else {
            return false;
        };
        let schedule = self.schedule.lock();
        schedule.head_revision == job.head_revision
            && schedule
                .committees
                .get(&(slot, committee))
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
                chain.task_executor.spawn_blocking(move || {
                    let result = match job.work() {
                        Work::Committee(slot, committee) => owner.prove_pq_committee(job, slot, committee),
                        Work::Initial(slot) | Work::Improvement(slot) => owner.prepare_pq_attestations(job, slot),
                        Work::Fallback(_) => Ok(()),
                    };
                    if let Err(error) = result {
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
    completed: bool,
}

impl<E: EthSpec> Active<E> {
    pub(super) fn release_unused(mut self) {
        self.scheduler.schedule.lock().active = None;
        self.completed = true;
        self.scheduler.changed.notify_one();
    }

    pub(crate) fn run(
        self,
        backend: impl FnOnce() -> Result<pq_prover::Proof, Error>,
    ) -> Result<pq_prover::Proof, Error> {
        let started = Instant::now();
        let result = backend();
        self.complete(&result, started.elapsed());
        result
    }

    fn complete(mut self, result: &Result<pq_prover::Proof, Error>, elapsed: Duration) {
        let uncertain = matches!(
            result,
            Err(Error::SidecarIo(_) | Error::SidecarProtocol(_) | Error::SidecarIncompatible(_))
        );
        let mut schedule = self.scheduler.schedule.lock();
        schedule.active = None;
        if matches!(self.work, Work::Committee(..)) {
            schedule.reservation_revision += 1;
        }
        schedule.unavailable |= uncertain;
        let measured_merge = matches!(
            result,
            Ok(_) | Err(Error::SidecarProvingFailed(_) | Error::SidecarClaimsMismatch { .. })
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
            warn!("PQ proving lane is unavailable after an ambiguous sidecar failure");
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
        BTreeMap::from([((Slot::new(1), committee), window)])
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
        assert_eq!(job.work(), Work::Committee(Slot::new(1), 0));
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
        let rejected = Err(Error::SidecarProvingFailed("test failure".into()));
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
        assert_eq!(old.work(), Work::Committee(Slot::new(1), 0));
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
        assert_eq!(current.work(), Work::Committee(Slot::new(1), 1));
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
                normal.run(|| Err(Error::SidecarInvalidInput("known completion".into()))),
                Err(Error::SidecarInvalidInput(_)),
            ));
            assert!(!scheduler.is_unavailable());
            assert!(harness.shutdown_reasons().is_empty());

            let failed = scheduler
                .start_fallback(now, Slot::new(1), now + seconds(1))
                .unwrap();
            assert!(matches!(
                failed.run(|| Err(Error::SidecarIo(std::io::ErrorKind::BrokenPipe.into()))),
                Err(Error::SidecarIo(_)),
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
        active.complete(
            &Err(Error::SidecarIo(std::io::ErrorKind::TimedOut.into())),
            seconds(1),
        );
        assert!(
            scheduler
                .start_fallback(seconds(24), TARGET, seconds(26))
                .is_none()
        );
    }
}
