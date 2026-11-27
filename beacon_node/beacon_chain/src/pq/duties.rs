//! Local duty discovery. The scheduler owns reservation timing and dispatch.

use super::prover_scheduler::{CommitteeDuties, ProposalDuties, proposal_window};
use crate::{
    BeaconChain, BeaconChainTypes, beacon_proposer_cache::compute_proposer_duties_from_head,
};
use parking_lot::Mutex;
use slot_clock::SlotClock;
use state_processing::pq::{self, MIN_ATTESTATION_INCLUSION_DELAY_PQ};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Notify;
use types::{Epoch, EthSpec, ForkName, RelativeEpoch, Slot};

#[derive(Default)]
pub(super) struct LocalDuties {
    attesters: Mutex<BTreeSet<(Epoch, u64)>>,
    changed: Notify,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn register_pq_aggregation_duty(&self, slot: Slot, committee: u64, validator_index: u64) {
        let Some(provers) = &self.pq_provers else {
            return;
        };
        let Some(current) = self.slot_clock.now_or_genesis() else {
            return;
        };
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        if self.spec.fork_name_at_slot::<T::EthSpec>(slot) != ForkName::Pq
            || slot < current
            || slot > current.saturating_add(slots_per_epoch.saturating_mul(2))
            || committee as usize >= T::EthSpec::max_committees_per_slot_pq()
            || self
                .head_snapshot()
                .beacon_state
                .get_validator(validator_index as usize)
                .is_err()
        {
            return;
        }
        provers
            .local_duties
            .attesters
            .lock()
            .insert((slot.epoch(slots_per_epoch), validator_index));
        provers.scheduler.suspend_measurements();
        self.refresh_pq_local_duties();
    }

    pub fn refresh_pq_local_duties(&self) {
        if let Some(provers) = &self.pq_provers {
            provers.local_duties.changed.notify_one();
            provers.scheduler.local_registrations_changed();
        }
    }

    pub(super) async fn has_pq_local_validators(&self) -> bool {
        if let Some(provers) = &self.pq_provers
            && let Some(slot) = self.slot_clock.now_or_genesis()
        {
            let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
            if provers
                .local_duties
                .attesters
                .lock()
                .range((epoch, 0)..)
                .next()
                .is_some()
            {
                return true;
            }
        }

        if let Some(execution_layer) = &self.execution_layer {
            return execution_layer.has_any_proposer_preparation_data().await;
        }
        false
    }

    pub fn refresh_pq_attester_duties(&self, epoch: Epoch, validators: &[u64]) {
        if let Some(provers) = &self.pq_provers {
            let known = provers.local_duties.attesters.lock();
            if validators
                .iter()
                .any(|&index| known.contains(&(epoch, index)))
            {
                provers.local_duties.changed.notify_one();
            }
        }
    }

    pub(super) fn start_pq_duty_updates(self: &Arc<Self>) {
        let chain = Arc::clone(self);
        self.task_executor.spawn(
            async move {
                let Some(provers) = &chain.pq_provers else {
                    return;
                };
                loop {
                    if chain.config.pq_measurement && chain.has_pq_local_validators().await {
                        provers.scheduler.suspend_measurements();
                    }
                    let owner = Arc::clone(&chain);
                    let Some(work) = chain.task_executor.spawn_blocking_handle(
                        move || owner.discover_pq_duties(),
                        "pq_discover_duties",
                    ) else {
                        return;
                    };
                    if let Ok(Some((committees, proposals, head_revision))) = work.await
                        && let Some(now) = chain.slot_clock.now_duration()
                    {
                        provers
                            .scheduler
                            .replace(now, committees, proposals, head_revision);
                    }

                    let next_slot = chain
                        .slot_clock
                        .duration_to_next_slot()
                        .unwrap_or(Duration::from_secs(1));
                    tokio::select! {
                        _ = provers.local_duties.changed.notified() => {},
                        _ = tokio::time::sleep(next_slot) => {},
                    }
                }
            },
            "pq_local_duties",
        );
    }

    fn discover_pq_duties(&self) -> Option<(CommitteeDuties, ProposalDuties, u64)> {
        let clock_slot = self.slot_clock.now_or_genesis()?;
        let provers = self.pq_provers.as_ref()?;
        let head_revision = provers.scheduler.head_revision();
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let epoch = clock_slot.epoch(slots_per_epoch);
        let mut state = self.head_beacon_state_cloned();

        let attesters = {
            let mut known = provers.local_duties.attesters.lock();
            known.retain(|(duty_epoch, _)| *duty_epoch >= epoch);
            known.clone()
        };
        let mut committees = CommitteeDuties::new();
        if state.build_all_committee_caches(&self.spec).is_ok() {
            for (duty_epoch, validator) in attesters {
                let Ok(relative) = RelativeEpoch::from_epoch(state.current_epoch(), duty_epoch)
                else {
                    continue;
                };
                let Ok(Some(duty)) = state.get_attestation_duties(validator as usize, relative)
                else {
                    continue;
                };
                if duty.slot >= clock_slot
                    && self.spec.fork_name_at_slot::<T::EthSpec>(duty.slot) == ForkName::Pq
                    && let Ok(Some(position)) =
                        pq::aggregator_position(&state, duty.slot, duty.index, validator)
                    && let Some(window) = self.pq_committee_window_at(duty.slot, position)
                {
                    if pq_measurement::global().is_some()
                        && let (Ok(beacon_committee), Ok(count)) = (
                            state.get_beacon_committee(duty.slot, duty.index),
                            state.get_committee_count_at_slot(duty.slot),
                        )
                    {
                        pq_measurement::duty::schedule(
                            pq_measurement::duty::committee_key(
                                duty.slot.as_u64(),
                                duty.index,
                                position,
                            ),
                            serde_json::json!({"kind":"committee","slot":duty.slot.as_u64(),
                                "committee_index":duty.index,"committee_members":beacon_committee.committee.len(),
                                "committees_per_slot":count,"aggregator_position":position,
                                "collection_unix_ns":window.start.as_nanos().to_string(),
                                "broadcast_unix_ns":window.end.as_nanos().to_string()}),
                            Some(validator),
                        );
                    }
                    committees.insert((duty.slot, duty.index, position), window);
                }
            }
        }

        let mut proposals = ProposalDuties::new();
        if let Some(el) = &self.execution_layer {
            let mut epochs = BTreeMap::new();
            // The following proposal's reservation can start before this target snapshots.
            for offset in 0..=MIN_ATTESTATION_INCLUSION_DELAY_PQ.saturating_add(1) {
                let slot = clock_slot.saturating_add(offset);
                if self.spec.fork_name_at_slot::<T::EthSpec>(slot) != ForkName::Pq {
                    continue;
                }
                let Some(vote_slot) = slot
                    .as_u64()
                    .checked_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ)
                    .map(Slot::new)
                else {
                    continue;
                };
                let duty_epoch = slot.epoch(slots_per_epoch);
                let duties = epochs.entry(duty_epoch).or_insert_with(|| {
                    compute_proposer_duties_from_head(duty_epoch, self)
                        .ok()
                        .map(|(indices, ..)| indices)
                });
                let within_epoch = slot.as_u64() % slots_per_epoch;
                if let Some(&validator) = duties
                    .as_ref()
                    .and_then(|indices| indices.get(within_epoch as usize))
                    && el.has_proposer_preparation_data_blocking(validator as u64)
                    && let (Some(vote_start), Some(target_start)) = (
                        self.slot_clock.start_of(vote_slot),
                        self.slot_clock.start_of(slot),
                    )
                {
                    self.common_proposal_known(slot, Some(validator as u64));
                    let (window, forecast) =
                        proposal_window(vote_start, target_start, self.slot_clock.slot_duration());
                    proposals.insert(slot, (window, forecast, validator as u64));
                }
            }
        }

        self.pq_signatures.lock().prune(clock_slot);
        self.op_pool.prune_pq_attestations(epoch);
        Some((committees, proposals, head_revision))
    }
}
