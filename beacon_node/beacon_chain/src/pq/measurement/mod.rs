//! PQ timing, observer inputs, and experimental duty policy.

mod controller;
mod recorder;

use super::{
    prover_scheduler::{Attempt, Work},
    signature_pool::{CommitteeInputs, SignaturePool},
};
use crate::{BeaconChain, BeaconChainTypes, canonical_head::CachedHead, metrics};
use operation_pool::{CompactIndexedAttestationPq, OperationPool};
use parking_lot::Mutex;
use rand::Rng;
use recorder::{Class, Record, Recorder};
use serde_json::{Value, json};
use slot_clock::SlotClock;
use ssz::ProgressiveBitList;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use types::{AttestationData, ChainSpec, EthSpec, Hash256, SingleAttestationPq, Slot};

pub(crate) const STRIDE: u64 = 3;
const MAX_PINS: usize = 2;

pub(crate) static RECORDER_EVENTS: LazyLock<metrics::Result<metrics::IntCounterVec>> =
    LazyLock::new(|| {
        metrics::try_create_int_counter_vec(
            "beacon_pq_timing_recorder_events_total",
            "PQ timing recorder outcomes by event class",
            &["class", "outcome"],
        )
    });

static EVENTS: LazyLock<metrics::Result<metrics::IntCounterVec>> = LazyLock::new(|| {
    metrics::try_create_int_counter_vec(
        "beacon_pq_timing_events_total",
        "PQ message and proving lifecycle outcomes",
        &["stage", "kind", "origin", "outcome"],
    )
});

static SECONDS: LazyLock<metrics::Result<metrics::HistogramVec>> = LazyLock::new(|| {
    metrics::try_create_histogram_vec(
        "beacon_pq_timing_seconds",
        "PQ slot, validation, scheduler and backend timing",
        &["stage", "kind", "origin"],
    )
});

pub(crate) fn wall_now_ns() -> u64 {
    ns(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default())
}

pub(super) fn ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn duration_metric(stage: &'static str, kind: &'static str, origin: &'static str, seconds: f64) {
    if let Some(metric) = metrics::get_histogram(&SECONDS, &[stage, kind, origin]) {
        metric.observe(seconds);
    }
}

pub(crate) fn proof_id(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    format!("{:#x}", Hash256::from_slice(&ethereum_hashing::hash(bytes)))
}

#[derive(Clone, Copy, Debug)]
pub enum GossipKind {
    Individual,
    Aggregate,
}

impl GossipKind {
    fn label(self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Aggregate => "aggregate",
        }
    }
}

#[derive(Clone, Copy)]
pub enum ValidationOutcome {
    Accepted,
    Duplicate,
    Deferred,
    Rejected,
    Ignored,
    QueueDropped,
    SyncDropped,
}

impl ValidationOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
            Self::Ignored => "ignored",
            Self::QueueDropped => "queue_dropped",
            Self::SyncDropped => "sync_dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Scenario {
    Committee,
    Proposer,
    Combined,
}

impl Scenario {
    fn label(self) -> &'static str {
        match self {
            Self::Committee => "committee_only",
            Self::Proposer => "proposer_only",
            Self::Combined => "combined",
        }
    }
}

#[derive(Clone)]
pub(super) struct Experiment {
    pub anchor: Slot,
    pub scenario: Scenario,
    pub committee_count: u64,
    pub active_validators: Option<usize>,
}

impl Experiment {
    fn id(&self) -> u64 {
        self.anchor.as_u64()
    }

    pub(super) fn target(&self) -> Slot {
        self.anchor.saturating_add(2u64)
    }
}

struct CommitteePin {
    experiment: u64,
    cutoff: Duration,
    expires: Duration,
    completed: bool,
    announced: bool,
}

struct ProposalPin<E: EthSpec> {
    experiment: u64,
    cutoff: Duration,
    deadline: Duration,
    latest: Slot,
    frozen: Option<FrozenInputs<E>>,
    snapshot_head: Option<CachedHead<E>>,
    announced: bool,
}

#[derive(Clone)]
pub(super) struct FrozenInputs<E: EthSpec> {
    pub(super) head: CachedHead<E>,
    pub(super) head_revision: u64,
    pub(super) cutoff: Duration,
    pub(super) captured_at: Duration,
    pub(super) candidates: Vec<Arc<CompactIndexedAttestationPq<E>>>,
}

struct Inputs<E: EthSpec> {
    network: OperationPool<E>,
    head: CachedHead<E>,
    head_revision: u64,
    signatures: SignaturePool<E>,
    experiments: BTreeMap<u64, Experiment>,
    committees: BTreeMap<(Slot, u64), CommitteePin>,
    proposals: BTreeMap<Slot, ProposalPin<E>>,
}

impl<E: EthSpec> Inputs<E> {
    fn freeze_due(&mut self, now: Duration) {
        for pin in self.proposals.values_mut() {
            if now >= pin.deadline && pin.snapshot_head.is_none() {
                pin.snapshot_head = Some(self.head.clone());
            }
            if pin.frozen.is_none() && pin.cutoff <= now && now < pin.deadline {
                pin.frozen = Some(FrozenInputs {
                    head: self.head.clone(),
                    head_revision: self.head_revision,
                    cutoff: pin.cutoff,
                    captured_at: now,
                    candidates: self.network.pq_attestation_candidates(pin.latest),
                });
            }
        }
    }

    fn prune(&mut self, now: Duration, slot: Slot) {
        self.freeze_due(now);
        self.signatures.prune(slot);
        self.network
            .prune_pq_attestations(slot.epoch(E::slots_per_epoch()));
    }
}

pub(crate) struct Measurement<E: EthSpec> {
    recorder: Option<Recorder>,
    origin: Instant,
    next_job: AtomicU64,
    seed: u64,
    inputs: Option<Mutex<Inputs<E>>>,
}

impl<E: EthSpec> Measurement<E> {
    pub(crate) fn new(
        output: Option<&Path>,
        observer: bool,
        genesis_time: u64,
        genesis_root: Hash256,
        network: Option<&str>,
        head: CachedHead<E>,
        spec: &ChainSpec,
    ) -> Result<Arc<Self>, String> {
        let origin = Instant::now();
        let start = wall_now_ns();
        let seed = rand::rng().random::<u64>();
        let id = format!("{start}-{seed:016x}");
        let recorder = output
            .map(|path| {
                let timing_slot = spec
                    .pq_fork_epoch
                    .map(|epoch| epoch.start_slot(E::slots_per_epoch()))
                    .unwrap_or(spec.genesis_slot);
                let attest = spec.get_attestation_due::<E>(timing_slot);
                let aggregate = spec.get_aggregate_attestation_due::<E>(timing_slot);
                Recorder::open(
                    path,
                    &id,
                    json!({
                        "schema_version": 1,
                        "run_id": id,
                        "started_unix_ns": start,
                        "observer": observer,
                        "network": network,
                        "genesis_time": genesis_time,
                        "genesis_slot": spec.genesis_slot.as_u64(),
                        "genesis_validators_root": genesis_root,
                        "lighthouse_version": lighthouse_version::version_with_platform(),
                        "lighthouse_commit": (!lighthouse_version::COMMIT.is_empty()).then_some(lighthouse_version::COMMIT),
                        "leanvm_revision": pq_prover::LEANVM_REV,
                        "leanvm_bindings_version": (pq_prover::LEANVM_REV == "241b009a61ba5fde797d1213b5bf76310f0d5060").then_some("0.16.0"),
                        "prover_backend": "leanvm-sidecar",
                        "prover_log_inv_rate": 2,
                        "prover_cpu_profile": Value::Null,
                        "prover_cpu_profile_requested": std::env::var("LEANVM_CPU_PROFILE").ok(),
                        "prover_threads": Value::Null,
                        "prover_threads_configured": std::env::var("LEANVM_THREADS").ok()
                            .and_then(|threads| threads.parse::<u64>().ok()),
                        "hardware": hardware(),
                        "timing": {
                            "slot_ns": ns(spec.get_slot_duration()),
                            "attestation_ns": ns(attest),
                            "committee_collection_ns": ns(attest + aggregate.saturating_sub(attest) / 2),
                            "aggregate_ns": ns(aggregate),
                            "initial_merge_ns": ns(super::prover_scheduler::INITIAL_DELAY),
                            "useful_margin_ns": ns(super::prover_scheduler::SAFETY_MARGIN),
                            "improvement_multiplier": super::prover_scheduler::MERGE_MULTIPLIER,
                            "reuse_estimate_ns": ns(super::prover_scheduler::SINGLE_COMMITTEE_ESTIMATE),
                            "proposal_lag_slots": 2,
                        },
                        "sampling": {"seed": seed, "anchor_phase": seed % STRIDE, "stride": STRIDE},
                        "receive_point": "decoded libp2p delivery, stamped before SSZ decode and after Snappy/dedup",
                    }),
                )
            })
            .transpose()?;
        Ok(Arc::new(Self {
            recorder,
            origin,
            next_job: AtomicU64::new(0),
            seed,
            inputs: observer.then(|| {
                Mutex::new(Inputs {
                    network: OperationPool::new(),
                    head,
                    head_revision: 0,
                    signatures: SignaturePool::default(),
                    experiments: BTreeMap::new(),
                    committees: BTreeMap::new(),
                    proposals: BTreeMap::new(),
                })
            }),
        }))
    }

    pub(crate) fn detailed(&self) -> bool {
        self.recorder.as_ref().is_some_and(Recorder::healthy)
    }

    fn emit_at(
        &self,
        class: Class,
        kind: &'static str,
        wall_ns: u64,
        instant: Instant,
        fields: impl FnOnce() -> Value,
    ) {
        if let Some(recorder) = self.recorder.as_ref().filter(|recorder| recorder.healthy()) {
            recorder.emit(
                class,
                Record {
                    kind,
                    wall_ns,
                    mono_ns: ns(instant.saturating_duration_since(self.origin)),
                    fields: fields(),
                },
            );
        }
    }

    fn emit(
        &self,
        class: Class,
        kind: &'static str,
        now: Duration,
        fields: impl FnOnce() -> Value,
    ) {
        self.emit_at(class, kind, ns(now), Instant::now(), fields);
    }

    pub(super) fn job(self: &Arc<Self>, job: Attempt, wall: Duration) -> Job<E> {
        let experiment = job
            .experiment()
            .and_then(|id| self.inputs.as_ref()?.lock().experiments.get(&id).cloned());
        Job {
            measurement: self.clone(),
            id: self
                .next_job
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
            experiment,
            experiment_id: job.experiment(),
            work: job.work(),
            scheduled_round: job.round(),
            depth: job.depth(),
            admitted_cutoff: job.cutoff(),
            enqueued_at: Instant::now(),
            wall,
        }
    }

    pub(crate) fn production_snapshot(
        &self,
        slot: Slot,
        now: Duration,
        candidate: Option<&super::attestation_preparation::PreparedAttestations<E>>,
        active: Option<(u64, Option<u64>)>,
    ) {
        let outcome = if candidate.is_some() {
            "candidate"
        } else {
            "no_candidate"
        };
        metrics::inc_counter_vec(
            &EVENTS,
            &["proposal_snapshot", "sequence", "production", outcome],
        );
        self.emit(Class::Status, "proposal_snapshot", now, || json!({
            "origin": "production", "scenario": "production",
            "sequence_id": format!("production:{slot}"), "reference_slot": slot.saturating_sub(2u64).as_u64(),
            "slot": slot.as_u64(), "outcome": outcome,
            "proof_id": candidate.map(|bundle| proof_id(&bundle.proof)),
            "participation": candidate.map(|bundle| bundle.participation),
            "records": candidate.map(|bundle| bundle.attestations.len()),
            "active_job_id": active.map(|entry| entry.0),
        }));
    }

    pub(crate) fn fallback_job(
        self: &Arc<Self>,
        slot: Slot,
        now: Duration,
        deadline: Duration,
    ) -> Job<E> {
        Job {
            measurement: self.clone(),
            id: self
                .next_job
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
            experiment: None,
            experiment_id: None,
            work: Work::Fallback(slot),
            scheduled_round: 1,
            depth: 0,
            admitted_cutoff: deadline,
            enqueued_at: Instant::now(),
            wall: now,
        }
    }

    pub(super) fn committee_completed(&self, slot: Slot, committee: u64, experiment: u64) {
        if let Some(inputs) = &self.inputs
            && let Some(pin) = inputs.lock().committees.get_mut(&(slot, committee))
            && pin.experiment == experiment
        {
            pin.completed = true;
        }
    }

    pub(crate) fn head_changed(&self, now: Duration, head: CachedHead<E>, revision: u64) {
        if let Some(inputs) = &self.inputs {
            let mut inputs = inputs.lock();
            inputs.freeze_due(now);
            inputs.head = head;
            inputs.head_revision = revision;
        }
    }

    pub(super) fn proposal_inputs(
        &self,
        job: Attempt,
        latest: Slot,
        now: Duration,
    ) -> Option<(
        Vec<Arc<CompactIndexedAttestationPq<E>>>,
        Option<FrozenInputs<E>>,
    )> {
        let mut inputs = self.inputs.as_ref()?.lock();
        inputs.freeze_due(now);
        let pin = inputs.proposals.get(&job.work().slot())?;
        if Some(pin.experiment) != job.experiment() || now >= pin.deadline {
            return None;
        }
        if matches!(job.work(), Work::Initial(_)) {
            let frozen = pin.frozen.clone()?;
            Some((frozen.candidates.clone(), Some(frozen)))
        } else {
            Some((inputs.network.pq_attestation_candidates(latest), None))
        }
    }

    pub(super) fn committee_input(
        &self,
        job: Attempt,
        slot: Slot,
        committee: u64,
    ) -> Option<Arc<CommitteeInputs>> {
        let inputs = self.inputs.as_ref()?.lock();
        let pin = inputs.committees.get(&(slot, committee))?;
        if Some(pin.experiment) != job.experiment() {
            return None;
        }
        inputs
            .signatures
            .best(slot, committee)
            .map(|(_, input)| Arc::clone(input))
    }

    pub(crate) fn insert_network(
        &self,
        epoch: types::Epoch,
        entry: Arc<CompactIndexedAttestationPq<E>>,
        now: impl FnOnce() -> Option<Duration>,
    ) -> bool {
        let Some(inputs) = &self.inputs else {
            return false;
        };
        let mut inputs = inputs.lock();
        let Some(now) = now() else {
            return false;
        };
        inputs.freeze_due(now);
        inputs.network.insert_pq_attestation(epoch, entry)
    }
}

pub(crate) struct Job<E: EthSpec> {
    measurement: Arc<Measurement<E>>,
    pub(super) id: u64,
    experiment: Option<Experiment>,
    experiment_id: Option<u64>,
    work: Work,
    scheduled_round: u64,
    depth: u64,
    admitted_cutoff: Duration,
    enqueued_at: Instant,
    wall: Duration,
}

impl<E: EthSpec> Job<E> {
    pub(crate) fn detailed(&self) -> bool {
        self.measurement.detailed()
    }

    pub(crate) fn emit(
        &self,
        event: &'static str,
        outcome: &'static str,
        now: Duration,
        fields: impl FnOnce() -> Value,
    ) {
        let work = self.work.label();
        let origin = if self.experiment_id.is_some() {
            "measurement"
        } else {
            "production"
        };
        metrics::inc_counter_vec(&EVENTS, &[event, work, origin, outcome]);
        self.measurement.emit(Class::Work, event, now, || {
            let mut data = fields();
            data["outcome"] = json!(outcome);
            data["job_id"] = json!(self.id);
            data["work"] = json!(work);
            data["origin"] = json!(origin);
            data["slot"] = json!(self.work.slot().as_u64());
            data["reference_slot"] = json!(self.work.reference_slot().as_u64());
            data["round"] = json!(self.scheduled_round);
            data["previous_recursive_depth"] = json!(self.depth);
            data["experiment_id"] = json!(self.experiment_id);
            data["sequence_id"] = json!(self.experiment_id.map_or_else(
                || format!("production:{}", self.work.slot()),
                |id| format!("measurement:{id}")
            ));
            data["scenario"] = json!(
                self.experiment
                    .as_ref()
                    .map(|experiment| experiment.scenario.label())
                    .unwrap_or("production")
            );
            data["committee_count"] = json!(
                self.experiment
                    .as_ref()
                    .map(|experiment| experiment.committee_count)
            );
            data["active_validators"] = json!(
                self.experiment
                    .as_ref()
                    .and_then(|experiment| experiment.active_validators)
            );
            data["scheduled_cutoff_ns"] = json!(ns(self.admitted_cutoff));
            data["enqueued_wall_ns"] = json!(ns(self.wall));
            data
        });
    }

    pub(crate) fn latency(&self, stage: &'static str, duration: Duration) {
        duration_metric(
            stage,
            self.work.label(),
            if self.experiment_id.is_some() {
                "measurement"
            } else {
                "production"
            },
            duration.as_secs_f64(),
        );
    }

    pub(super) fn queue_wait(&self) -> Duration {
        self.enqueued_at.elapsed()
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn record_pq_gossip_receive(
        &self,
        kind: GossipKind,
        id: impl FnOnce() -> String,
        data: &AttestationData,
        committee: Option<u64>,
        subnet: Option<u64>,
        signers: usize,
        bytes: usize,
        wall_ns: u64,
        instant: Instant,
    ) {
        let label = kind.label();
        metrics::inc_counter_vec(&EVENTS, &["message_received", label, "network", "seen"]);
        if let Some(start) = self.slot_clock.start_of(data.slot) {
            let offset = (i128::from(wall_ns) - i128::from(ns(start))) as f64 * 1e-9;
            duration_metric("receive_offset", label, "network", offset);
        }
        self.pq_measurement
            .emit_at(Class::Receipt, "message_received", wall_ns, instant, || {
                use tree_hash::TreeHash;
                json!({
                    "message_kind": label, "message_id": id(), "source": "network",
                    "reference_slot": data.slot.as_u64(), "slot": data.slot.as_u64(),
                    "committee": committee, "subnet": subnet, "message_bytes": bytes,
                    "byte_basis": "decoded_ssz", "signer_count": signers,
                    "vote_data_root": data.tree_hash_root(),
                })
            });
    }

    pub fn record_pq_gossip_validation(
        &self,
        kind: GossipKind,
        id: impl FnOnce() -> String,
        slot: Slot,
        received: Option<Instant>,
        completed: Instant,
        completed_wall_ns: u64,
        outcome: ValidationOutcome,
    ) {
        metrics::inc_counter_vec(
            &EVENTS,
            &["validated", kind.label(), "network", outcome.label()],
        );
        let latency = received.map(|instant| completed.saturating_duration_since(instant));
        if let Some(latency) = latency {
            duration_metric("validation", kind.label(), "network", latency.as_secs_f64());
        }
        self.pq_measurement.emit_at(
            Class::Validation,
            "validated",
            completed_wall_ns,
            completed,
            || {
                json!({
                    "message_kind": kind.label(), "message_id": id(), "source": "network",
                    "reference_slot": slot.as_u64(), "slot": slot.as_u64(),
                    "outcome": outcome.label(), "receipt_to_validation_ns": latency.map(ns),
                })
            },
        );
    }

    pub fn record_pq_network_candidate(
        &self,
        message_id: impl FnOnce() -> String,
        entry: &CompactIndexedAttestationPq<T::EthSpec>,
        inserted: bool,
    ) {
        let Some(now) = self.slot_clock.now_duration() else {
            return;
        };
        self.pq_measurement.emit(Class::Validation, "network_candidate", now, || {
            json!({
                "message_id": message_id(), "reference_slot": entry.attestation.data.slot.as_u64(),
                "source": "network", "pool_changed": inserted,
                "proof_id": proof_id(&entry.proof),
            })
        });
    }

    pub(crate) fn observe_pq_network_signature(
        &self,
        attestation: &SingleAttestationPq,
        bits: &ProgressiveBitList,
    ) {
        let Some(inputs) = &self.pq_measurement.inputs else {
            return;
        };
        let Some(provers) = &self.pq_provers else {
            return;
        };
        let key = (attestation.data.slot, attestation.committee_index);
        let priority = {
            let mut inputs = inputs.lock();
            let Some(now) = self.slot_clock.now_duration() else {
                return;
            };
            let Some(slot) = self.slot_clock.slot_of(now) else {
                return;
            };
            if !inputs
                .committees
                .get(&key)
                .is_some_and(|pin| now < pin.cutoff)
            {
                return;
            }
            inputs.signatures.insert(slot, attestation, bits)
        };
        if let Some(priority) = priority {
            provers
                .scheduler
                .measurement_committee_changed(key.0, key.1, priority);
        }
    }
}

fn hardware() -> Value {
    fn field(file: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(file)
            .ok()?
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.trim() == key).then(|| value.trim().to_string())
            })
    }

    let cpu = field("/proc/cpuinfo", "model name").or_else(|| field("/proc/cpuinfo", "Hardware"));
    let mem_bytes = field("/proc/meminfo", "MemTotal")
        .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
        .and_then(|kib| kib.checked_mul(1024));
    let (quota, memory_limit) = cgroup_limits();
    let effective_cpus = std::thread::available_parallelism()
        .ok()
        .map(|count| count.get());
    json!({
        "architecture": std::env::consts::ARCH, "os": std::env::consts::OS,
        "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|value| value.trim().to_string()),
        "cpu_model": cpu,
        "available_parallelism": effective_cpus,
        "cpu_affinity": field("/proc/self/status", "Cpus_allowed_list"),
        "cgroup_cpu_equivalents": quota,
        "visible_memory_bytes": mem_bytes,
        "cgroup_memory_bytes": memory_limit,
    })
}

fn cgroup_limits() -> (Option<f64>, Option<u64>) {
    let root = Path::new("/sys/fs/cgroup");
    let group = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|data| {
            data.lines()
                .find_map(|line| line.strip_prefix("0::/").map(str::to_owned))
        })
        .unwrap_or_default();
    let mut path = root.join(group);
    if !path.is_dir() {
        path = root.to_path_buf();
    }
    let cpu = |path: &Path| {
        let value = std::fs::read_to_string(path.join("cpu.max")).ok()?;
        let (quota, period) = value.trim().split_once(' ')?;
        let period = period.parse::<u64>().ok().filter(|value| *value > 0)?;
        Some(quota.parse::<u64>().ok()? as f64 / period as f64)
    };
    let memory = |path: &Path| {
        std::fs::read_to_string(path.join("memory.max"))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    };
    let paths = || {
        path.ancestors()
            .take_while(|parent| parent.starts_with(root))
    };
    (
        paths().filter_map(cpu).reduce(f64::min),
        paths().filter_map(memory).min(),
    )
}

#[cfg(all(test, feature = "spec-minimal", not(debug_assertions)))]
mod tests {
    use super::*;
    use crate::{
        chain_config::{ChainConfig, PqProverConfig},
        pq::prover_scheduler::{Window, committee_window, proposal_window},
        test_utils::{BeaconChainHarness, EphemeralHarnessType},
    };
    use state_processing::pq;
    use types::{Attestation, ForkName, MinimalEthSpec};

    #[tokio::test]
    async fn pq_observer_freezes_network_inputs_and_keeps_private_proofs_isolated() {
        type E = MinimalEthSpec;
        let output = tempfile::tempdir().unwrap();
        let spec = Arc::new(ForkName::Pq.make_genesis_spec(E::default_spec()));
        let config = ChainConfig {
            pq_measurement: true,
            pq_timing_output: Some(output.path().to_path_buf()),
            pq_prover: std::env::var_os("PQ_MEASUREMENT_TEST_SOCKET")
                .map(|socket| PqProverConfig::Sidecar(socket.into())),
            ..ChainConfig::default()
        };
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec.clone())
            .deterministic_keypairs((2 * E::slots_per_epoch()) as usize)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .chain_config(config)
            .build();
        let chain = &harness.chain;
        let prover = chain.pq_provers.as_ref().unwrap();
        let scheduler = &prover.scheduler;
        let measurement = &chain.pq_measurement;
        let slot = Slot::new(0);
        let target = Slot::new(2);
        let start = chain.slot_clock.start_of(slot).unwrap();
        let deadline = chain.slot_clock.start_of(target).unwrap();
        let committee = committee_window(
            start,
            spec.get_attestation_due::<E>(slot),
            spec.get_aggregate_attestation_due::<E>(slot),
        );
        let (proposal_window, _) =
            proposal_window(start, deadline, chain.slot_clock.slot_duration());
        let proposal = Window {
            end: deadline,
            ..proposal_window
        };
        let id = 0;
        measurement
            .inputs
            .as_ref()
            .unwrap()
            .lock()
            .committees
            .insert(
                (slot, 0),
                CommitteePin {
                    experiment: id,
                    cutoff: committee.start,
                    expires: committee.end,
                    completed: false,
                    announced: false,
                },
            );
        measurement
            .inputs
            .as_ref()
            .unwrap()
            .lock()
            .proposals
            .insert(
                target,
                ProposalPin {
                    experiment: id,
                    cutoff: proposal.start,
                    deadline,
                    latest: slot,
                    frozen: None,
                    snapshot_head: None,
                    announced: false,
                },
            );
        assert!(scheduler.register_measurement(
            id,
            start,
            Some(((slot, 0), committee)),
            Some((target, proposal))
        ));

        let state = harness.get_current_state();
        let Attestation::Pq(attestation) = chain.produce_unaggregated_attestation(slot, 0).unwrap()
        else {
            panic!("expected PQ aggregate data");
        };
        let expected = state.get_beacon_committee(slot, 0).unwrap();
        assert_eq!(expected.committee.len(), 2);

        let make_signature = |position: usize| {
            let signer = expected.committee[position];
            let statement =
                pq::attestation_statement(&state, &attestation.data, &[signer as u64], &spec)
                    .unwrap();
            let signature = harness.sign_pq_test_message(
                signer,
                statement.leaf_index,
                Hash256::from(statement.message),
            );
            SingleAttestationPq {
                committee_index: 0,
                attester_index: signer as u64,
                data: attestation.data.clone(),
                signature,
            }
        };
        let first = make_signature(0);
        let second = make_signature(1);
        let mut bits = attestation.aggregation_bits.clone();
        bits.set(0, true).unwrap();
        chain
            .slot_clock
            .set_current_time(committee.start - Duration::from_millis(1));
        chain.observe_pq_network_signature(&first, &bits);
        chain.slot_clock.set_current_time(committee.start);
        bits.set(0, false).unwrap();
        bits.set(1, true).unwrap();
        chain.observe_pq_network_signature(&second, &bits);
        let committee_job = scheduler.next(committee.start).unwrap();
        let signers = measurement.committee_input(committee_job, slot, 0).unwrap();
        assert_eq!(signers.signature_count(), 1);
        let trace = measurement.job(committee_job, committee.start);
        chain
            .prove_pq_committee(committee_job, slot, 0, &trace)
            .unwrap();
        use tree_hash::TreeHash;
        assert!(
            chain
                .pq_aggregate(slot, attestation.data.tree_hash_root(), 0)
                .is_none()
        );
        assert!(chain.op_pool.pq_attestation_candidates(slot).is_empty());
        assert!(
            measurement
                .inputs
                .as_ref()
                .unwrap()
                .lock()
                .network
                .pq_attestation_candidates(slot)
                .is_empty()
        );

        let aggregate = |signatures: &[SingleAttestationPq]| {
            let mut aggregate = attestation.clone();
            for position in 0..signatures.len() {
                aggregate.aggregation_bits.set(position, true).unwrap();
            }
            let indices = signatures
                .iter()
                .map(|signature| signature.attester_index)
                .collect::<Vec<_>>();
            let statement =
                pq::attestation_statement(&state, &aggregate.data, &indices, &spec).unwrap();
            let batch = signatures
                .iter()
                .map(|signature| signature.signature.clone())
                .collect();
            let proof = prover
                .aggregate
                .prove(std::slice::from_ref(&statement), &[batch])
                .unwrap();
            let mut attesting_indices = indices;
            attesting_indices.sort_unstable();
            Arc::new(CompactIndexedAttestationPq {
                attestation: aggregate,
                attesting_indices,
                statement,
                proof: proof.into_bytes().try_into().unwrap(),
            })
        };
        let narrow = aggregate(std::slice::from_ref(&first));
        let wide = aggregate(&[first, second]);
        assert!(
            measurement.insert_network(state.current_epoch(), Arc::clone(&narrow), || Some(
                proposal.start - Duration::from_millis(1)
            ))
        );
        assert!(
            measurement.insert_network(state.current_epoch(), Arc::clone(&wide), || Some(
                proposal.start
            ))
        );
        scheduler.measurement_aggregate_changed();
        chain
            .slot_clock
            .set_current_time(proposal.start + Duration::from_millis(1));

        let initial = scheduler.next(proposal.start).unwrap();
        let (frozen, _) = measurement
            .proposal_inputs(initial, slot, proposal.start)
            .unwrap();
        let [selected] = frozen.as_slice() else {
            panic!("expected sole frozen network candidate");
        };
        assert!(Arc::ptr_eq(selected, &narrow));
        chain.prepare_pq_attestations(initial, target).unwrap();

        let next = scheduler
            .next(proposal.start + Duration::from_millis(1))
            .unwrap();
        assert_eq!(next.round(), 2);
        assert_eq!(next.depth(), 0);
        chain.prepare_pq_attestations(next, target).unwrap();

        assert!(
            scheduler
                .snapshot(target, deadline, deadline, chain.slot_clock.slot_duration())
                .is_none()
        );
        let (ready, round, depth, calls, _) = scheduler.measurement_snapshot(target, id, deadline);
        let ready = ready.unwrap();
        assert_eq!(ready.statements[0].pubkeys.len(), 2);
        assert_eq!(round, 2);
        assert_eq!(depth, 1);
        assert_eq!(calls, 1);
        assert!(chain.op_pool.pq_attestation_candidates(slot).is_empty());
    }
}
