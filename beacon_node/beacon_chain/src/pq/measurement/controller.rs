//! The observer announces fixed synthetic duties. The shared scheduler admits and runs them.

use super::{
    Class, CommitteePin, Experiment, MAX_PINS, ProposalPin, STRIDE, Scenario, ns, proof_id,
};
use crate::{
    BeaconChain, BeaconChainTypes, block_production::pq::attestation_packing::ProposalView,
    pq::prover_scheduler::proposal_window,
};
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
use serde_json::json;
use slot_clock::SlotClock;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use types::{EthSpec, ForkName, RelativeEpoch, Slot};

#[derive(Default)]
struct CommitteeDraws(BTreeMap<(u64, u64), u64>);

impl CommitteeDraws {
    fn draw(&mut self, seed: u64, scenario: Scenario, count: u64) -> Option<(u64, u64)> {
        if count == 0 {
            return None;
        }
        let stream = scenario as u64;
        let draw = self.0.entry((stream, count)).or_default();
        let ordinal = *draw;
        *draw = draw.saturating_add(1u64);
        let mut permutation = (0..count).collect::<Vec<_>>();
        let mut rng = StdRng::seed_from_u64(
            seed ^ stream.rotate_left(11)
                ^ count.rotate_left(19)
                ^ (ordinal / count).rotate_left(41),
        );
        permutation.shuffle(&mut rng);
        permutation
            .get((ordinal % count) as usize)
            .copied()
            .map(|index| (index, ordinal))
    }
}

fn next_anchor(slot: Slot, phase: u64) -> Slot {
    let next = slot.saturating_add(1u64);
    next.saturating_add((STRIDE + phase - next.as_u64() % STRIDE) % STRIDE)
}

fn scenario(anchor: Slot) -> Scenario {
    match (anchor.as_u64() / STRIDE) % 3 {
        0 => Scenario::Committee,
        1 => Scenario::Proposer,
        _ => Scenario::Combined,
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn start_pq_measurement(
        self: &Arc<Self>,
        network_status: impl Fn() -> (bool, usize) + Send + Sync + 'static,
    ) {
        if !self.config.pq_measurement && !self.pq_measurement.detailed() {
            return;
        }
        let chain = Arc::clone(self);
        self.task_executor.spawn(
            async move {
                let measurement = &chain.pq_measurement;
                let phase = measurement.seed % STRIDE;
                let mut planned = None;
                let mut draws = CommitteeDraws::default();
                let mut last_status = None;
                let mut prior_clock: Option<(Duration, Instant)> = None;
                loop {
                    let Some(now) = chain.slot_clock.now_duration() else {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    let Some(slot) = chain.slot_clock.slot_of(now) else {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    let wall_mono = Instant::now();
                    if let Some((old_wall, old_mono)) = prior_clock {
                        let elapsed = wall_mono.saturating_duration_since(old_mono);
                        let expected = old_wall.saturating_add(elapsed);
                        if now.abs_diff(expected) >= Duration::from_millis(500) {
                            measurement.emit(Class::Status, "clock_discontinuity", now, || json!({
                                "previous_wall_ns": ns(old_wall), "expected_wall_ns": ns(expected),
                                "monotonic_elapsed_ns": ns(elapsed),
                            }));
                        }
                    }
                    prior_clock = Some((now, wall_mono));
                    let (synced, peers) = network_status();
                    let status = (synced, peers);
                    if last_status != Some(status) {
                        measurement.emit(Class::Status, "network_status", now, || {
                        json!({"synced": synced, "connected_peers": peers, "slot": slot.as_u64()})
                    });
                        last_status = Some(status);
                    }
                    if let Some(provers) = &chain.pq_provers
                        && chain.config.pq_measurement
                    {
                        chain.close_pq_measurements(slot, now);
                        let local = chain.has_pq_local_validators().await;
                        let usable = synced
                            && !local
                            && measurement.detailed()
                            && provers.scheduler.is_ready_for_observation();
                        if !usable {
                            provers.scheduler.withdraw_measurements();
                        }
                        if planned.is_none_or(|anchor| slot >= anchor) {
                            let mut anchor = planned.map_or_else(
                                || next_anchor(slot, phase),
                                |last: Slot| last.saturating_add(STRIDE),
                            );
                            if anchor <= slot {
                                let missed = (slot.as_u64() - anchor.as_u64()) / STRIDE + 1;
                                measurement.emit(Class::Status, "experiment_gap", now, || {
                                    json!({
                                        "first_anchor": anchor.as_u64(), "count": missed,
                                        "stride": STRIDE, "outcome": "missed_anchor",
                                    })
                                });
                                anchor = next_anchor(slot, phase);
                            }
                            let reason = if local {
                                "local_validators"
                            } else if !synced {
                                "syncing"
                            } else if !measurement.detailed() {
                                "recorder_unavailable"
                            } else {
                                "prover_unavailable"
                            };
                            if usable
                                && chain.spec.fork_name_at_slot::<T::EthSpec>(anchor)
                                    == ForkName::Pq
                            {
                                let owner = Arc::clone(&chain);
                                let Some(work) = chain.task_executor.spawn_blocking_handle(
                                    move || owner.pq_sample_geometry(anchor),
                                    "pq_measurement_geometry",
                                ) else {
                                    return;
                                };
                                match work.await {
                                    Ok(Some((count, active, head))) => chain.plan_pq_measurement(
                                        anchor, count, active, head, &mut draws,
                                    ),
                                    _ => chain.report_pq_planned(anchor, now, "missing_geometry"),
                                }
                            } else {
                                chain.report_pq_planned(
                                    anchor,
                                    now,
                                    if usable { "pre_pq" } else { reason },
                                );
                            }
                            planned = Some(anchor);
                        }
                    }
                    let wall = chain.slot_clock.now_duration().unwrap_or(now);
                    let next_slot = chain
                        .slot_clock
                        .duration_to_next_slot()
                        .unwrap_or(Duration::from_secs(1));
                    let deadline = measurement.inputs.as_ref().and_then(|inputs| {
                        let inputs = inputs.lock();
                        let committee_boundaries = inputs
                            .committees
                            .values()
                            .flat_map(|pin| [pin.cutoff, pin.expires]);
                        let proposal_boundaries = inputs
                            .proposals
                            .values()
                            .flat_map(|pin| [pin.cutoff, pin.deadline]);
                        committee_boundaries
                            .chain(proposal_boundaries)
                            .filter(|at| *at > wall)
                            .min()
                    });
                    let delay =
                        deadline.map_or(next_slot, |at| at.saturating_sub(wall).min(next_slot));
                    tokio::time::sleep(delay.max(Duration::from_millis(1))).await;
                }
            },
            "pq_measurement",
        );
    }

    fn pq_sample_geometry(&self, anchor: Slot) -> Option<(u64, Option<usize>, types::Hash256)> {
        let sample_slot = if scenario(anchor) == Scenario::Combined {
            anchor.saturating_add(1u64)
        } else {
            anchor
        };
        let head = self.canonical_head.cached_head();
        let mut state = head.snapshot.beacon_state.clone();
        state.build_all_committee_caches(&self.spec).ok()?;
        let count = state.get_committee_count_at_slot(sample_slot).ok()?;
        let epoch = sample_slot.epoch(T::EthSpec::slots_per_epoch());
        let active = RelativeEpoch::from_epoch(state.current_epoch(), epoch)
            .ok()
            .and_then(|relative| state.get_cached_active_validator_indices(relative).ok())
            .map(|indices| indices.len());
        Some((count, active, head.head_block_root()))
    }

    fn report_pq_planned(&self, anchor: Slot, now: Duration, outcome: &'static str) {
        super::metrics::inc_counter_vec(
            &super::EVENTS,
            &["experiment_planned", "sequence", "measurement", outcome],
        );
        self.pq_measurement
            .emit(Class::Status, "experiment_planned", now, || {
                json!({
                    "experiment_id": anchor.as_u64(), "reference_slot": anchor.as_u64(),
                    "scenario": scenario(anchor).label(), "outcome": outcome,
                })
            });
    }

    fn plan_pq_measurement(
        &self,
        anchor: Slot,
        count: u64,
        active_validators: Option<usize>,
        head: types::Hash256,
        draws: &mut CommitteeDraws,
    ) {
        let Some(provers) = &self.pq_provers else {
            return;
        };
        let measurement = &self.pq_measurement;
        let Some(input_lock) = &measurement.inputs else {
            return;
        };
        let Some(now) = self.slot_clock.now_duration() else {
            return;
        };
        let Some(start) = self.slot_clock.start_of(anchor) else {
            return;
        };
        let scenario = scenario(anchor);
        let experiment = Experiment {
            anchor,
            scenario,
            committee_count: count,
            active_validators,
        };
        let id = experiment.id();
        let mut draw_number = None;
        let committee = if scenario != Scenario::Proposer {
            let Some((committee, draw)) = draws.draw(measurement.seed, scenario, count) else {
                self.report_pq_planned(anchor, now, "missing_geometry");
                return;
            };
            draw_number = Some(draw);
            let slot = if scenario == Scenario::Combined {
                anchor.saturating_add(1u64)
            } else {
                anchor
            };
            let Some(window) = self.pq_committee_window(slot) else {
                self.report_pq_planned(anchor, now, "missing_clock");
                return;
            };
            Some(((slot, committee), window))
        } else {
            None
        };
        let proposal = if scenario != Scenario::Committee {
            let slot = experiment.target();
            let Some(target) = self.slot_clock.start_of(slot) else {
                self.report_pq_planned(anchor, now, "missing_clock");
                return;
            };
            let (mut window, _) = proposal_window(start, target, self.slot_clock.slot_duration());
            window.end = target;
            Some((slot, window))
        } else {
            None
        };
        if now >= start {
            self.report_pq_planned(anchor, now, "missed_preselection");
            return;
        }
        {
            let mut inputs = input_lock.lock();
            if inputs.proposals.len() >= MAX_PINS || inputs.committees.len() >= MAX_PINS {
                self.report_pq_planned(anchor, now, "pin_capacity");
                return;
            }
            inputs.experiments.insert(id, experiment.clone());
            if let Some((key, window)) = committee {
                inputs.committees.insert(
                    key,
                    CommitteePin {
                        experiment: id,
                        cutoff: window.start,
                        expires: window.end,
                        completed: false,
                        announced: false,
                    },
                );
            }
            if let Some((slot, window)) = proposal {
                inputs.proposals.insert(
                    slot,
                    ProposalPin {
                        experiment: id,
                        cutoff: window.start,
                        deadline: window.end,
                        latest: anchor,
                        frozen: None,
                        snapshot_head: None,
                        announced: false,
                    },
                );
            }
        }
        if !provers
            .scheduler
            .register_measurement(id, now, committee, proposal)
        {
            let mut inputs = input_lock.lock();
            inputs.experiments.remove(&id);
            inputs.committees.retain(|_, pin| pin.experiment != id);
            inputs.proposals.retain(|_, pin| pin.experiment != id);
            self.report_pq_planned(anchor, now, "reservation_unavailable");
            return;
        }
        super::metrics::inc_counter_vec(
            &super::EVENTS,
            &["experiment_planned", "sequence", "measurement", "planned"],
        );
        measurement.emit(Class::Status, "experiment_planned", now, || json!({
            "experiment_id": id, "sequence_id": format!("measurement:{id}"),
            "reference_slot": anchor.as_u64(), "scenario": scenario.label(), "outcome": "planned",
            "target_slot": proposal.map(|(slot, _)| slot.as_u64()),
            "committee_slot": committee.map(|((slot, _), _)| slot.as_u64()),
            "committee": committee.map(|((_, committee), _)| committee),
            "committee_count": count, "active_validators": active_validators,
            "committee_draw": draw_number, "head_root": head,
            "scheduled_committee_wall_ns": committee.map(|(_, window)| ns(window.start)),
            "scheduled_initial_wall_ns": proposal.map(|(_, window)| ns(window.start)),
        }));
    }

    fn close_pq_measurements(self: &Arc<Self>, slot: Slot, now: Duration) {
        let measurement = &self.pq_measurement;
        let Some(input_lock) = &measurement.inputs else {
            return;
        };
        let Some(provers) = &self.pq_provers else {
            return;
        };
        let active = provers.scheduler.active_job();
        let mut cutoffs = Vec::new();
        let mut expired = Vec::new();
        let mut snapshots = Vec::new();
        {
            let mut inputs = input_lock.lock();
            inputs.prune(now, slot);
            inputs.committees.retain(|&key, pin| {
                if now >= pin.cutoff && !pin.announced {
                    cutoffs.push((pin.experiment, key.0, "committee", pin.cutoff));
                    pin.announced = true;
                }
                if now >= pin.expires && !pin.completed {
                    expired.push((pin.experiment, key.0, pin.expires));
                }
                now < pin.expires
            });
            for (&target, pin) in inputs.proposals.iter_mut() {
                if now >= pin.cutoff && !pin.announced {
                    cutoffs.push((pin.experiment, target, "initial", pin.cutoff));
                    pin.announced = true;
                }
                if now >= pin.deadline {
                    snapshots.push((
                        pin.experiment,
                        target,
                        pin.deadline,
                        pin.snapshot_head.take(),
                    ));
                }
            }
            for (_, slot, _, _) in &snapshots {
                inputs.proposals.remove(slot);
            }
            inputs
                .experiments
                .retain(|anchor, _| anchor.saturating_add(3 * STRIDE) >= slot.as_u64());
        }
        for (id, slot, kind, cutoff) in cutoffs {
            measurement.emit(Class::Status, "input_cutoff", now, || json!({
                "experiment_id": id, "slot": slot.as_u64(), "work": kind,
                "scheduled_cutoff_wall_ns": ns(cutoff), "active_job_id": active.map(|entry| entry.0),
                "active_experiment_id": active.and_then(|entry| entry.1),
                "foreign_overrun": active.is_some_and(|(_, experiment)| experiment != Some(id)),
            }));
        }
        for (id, slot, deadline) in expired {
            super::metrics::inc_counter_vec(
                &super::EVENTS,
                &["job_outcome", "committee", "measurement", "expired"],
            );
            measurement.emit(Class::Status, "job_outcome", now, || {
                json!({
                    "experiment_id": id, "slot": slot.as_u64(), "work": "committee",
                    "outcome": "expired", "deadline_wall_ns": ns(deadline),
                })
            });
        }
        for (id, slot, deadline, head) in snapshots {
            let (candidate, round, depth, calls, active) =
                provers.scheduler.measurement_snapshot(slot, id, now);
            let chain = Arc::clone(self);
            self.task_executor.spawn_blocking(move || {
                let Some(experiment) = chain.pq_measurement.inputs.as_ref()
                    .and_then(|inputs| inputs.lock().experiments.get(&id).cloned()) else { return; };
                let context = head.as_ref().and_then(|head| {
                    chain.speculative_pq_state_from_head(slot, head).ok().flatten()
                });
                let usable = candidate.as_ref().filter(|bundle| {
                    context.as_ref().is_some_and(|(state, parent)| {
                        ProposalView::new(state, &chain.spec, parent.as_ref()).is_ok_and(|view| {
                            view.bundle_is_valid(&bundle.attestations, &bundle.statements)
                        })
                    })
                });
                let outcome = if usable.is_some() { "ready" } else if candidate.is_some() { "invalid_context" }
                    else if active.is_some_and(|(_, experiment)| experiment == Some(id)) { "in_flight" }
                    else { "no_candidate" };
                super::metrics::inc_counter_vec(&super::EVENTS, &["proposal_snapshot", "sequence", "measurement", outcome]);
                chain.pq_measurement.emit(Class::Status, "proposal_snapshot", now, || json!({
                    "experiment_id": id, "sequence_id": format!("measurement:{id}"),
                    "scenario": experiment.scenario.label(), "reference_slot": experiment.anchor.as_u64(),
                    "committee_count": experiment.committee_count, "active_validators": experiment.active_validators,
                    "slot": slot.as_u64(), "nominal_snapshot_wall_ns": ns(deadline),
                    "outcome": outcome, "round": if usable.is_some() { round } else { 0 },
                    "recursive_depth": if usable.is_some() { depth } else { 0 },
                    "backend_call_count": calls,
                    "parent_root": head.as_ref().map(|head| head.head_block_root()),
                    "participation": usable.map(|bundle| bundle.participation),
                    "claims": usable.map(|bundle| bundle.statements.iter().map(|s| s.pubkeys.len()).sum::<usize>()),
                    "records": usable.map(|bundle| bundle.attestations.len()),
                    "proof_id": usable.map(|bundle| proof_id(&bundle.proof)),
                    "active_job_id": active.map(|entry| entry.0),
                    "foreign_overrun": active.is_some_and(|(_, owner)| owner != Some(id)),
                }));
            }, "pq_measurement_snapshot");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_cadence_alternates_slots_and_rotates_scenarios() {
        let first = next_anchor(Slot::new(8), 1);
        assert_eq!(first, Slot::new(10));
        let samples = (0..100)
            .map(|n| first.saturating_add(n * STRIDE))
            .collect::<Vec<_>>();
        for pair in samples.windows(2) {
            assert_ne!(pair[0].as_u64() % 2, pair[1].as_u64() % 2);
            assert_ne!(scenario(pair[0]), scenario(pair[1]));
        }
        assert_eq!(samples.last().unwrap().as_u64() - first.as_u64(), 297);
    }

    #[test]
    fn seeded_choice_balances_each_complete_cycle() {
        let sample = || {
            let mut draws = CommitteeDraws::default();
            (0..24)
                .map(|_| draws.draw(319, Scenario::Combined, 8).unwrap().0)
                .collect::<Vec<_>>()
        };
        let choices = sample();
        assert_eq!(choices, sample());
        for cycle in choices.chunks(8) {
            let mut sorted = cycle.to_vec();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..8).collect::<Vec<_>>());
        }
    }
}
