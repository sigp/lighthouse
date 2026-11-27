//! Thin production hook adapters for the common, separately enabled measurement stream.
use super::prover_scheduler::Attempt;
use crate::{BeaconChain, BeaconChainTypes};
use pq_measurement::{Mode, duty, proof::Plan};
use serde_json::json;
use slot_clock::SlotClock;
use types::Slot;

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub(crate) fn common_proposal_known(&self, slot: Slot, validator: Option<u64>) {
        if pq_measurement::global().is_none() {
            return;
        }
        if validator.is_none() && duty::get(&duty::proposal_key(slot.as_u64())).is_some() {
            return;
        }
        if let Some(start) = self.slot_clock.start_of(slot) {
            duty::schedule(
                duty::proposal_key(slot.as_u64()),
                json!({
                    "kind":"proposal","slot":slot.as_u64(),"proposal_unix_ns":start.as_nanos().to_string()
                }),
                validator,
            );
        }
    }

    pub(super) fn common_committee_plan(
        &self,
        job: Attempt,
        slot: Slot,
        committee: u64,
        position: u64,
        members: usize,
        committees: u64,
        signatures: usize,
    ) -> Option<Plan> {
        let recorder = pq_measurement::global()?;
        let key = duty::committee_key(slot.as_u64(), committee, position);
        let owner = duty::get(&key);
        let experiment =
            job.experiment().is_some() || (self.config.pq_aggregate_all && owner.is_none());
        if !experiment && owner.is_none() {
            recorder.record_summary_eviction("pq.operation_admitted");
            return None;
        }
        let mode = if experiment {
            Mode::Experiment
        } else {
            Mode::Production
        };
        Plan::new(
            mode,
            json!({"kind":"committee","purpose":if owner.is_some(){"committee_duty"}else{"reusable_preparation"},
            "vote_slot":slot.as_u64(),"committee_index":committee,"committees_per_slot":committees,
            "committee_members":members,"signatures":signatures}),
            owner,
        )
    }

    pub(crate) fn common_merge_plan(
        &self,
        slot: Slot,
        experiment: bool,
        vote_slots: Vec<u64>,
    ) -> Option<Plan> {
        let recorder = pq_measurement::global()?;
        let owner = if experiment {
            None
        } else {
            duty::get(&duty::proposal_key(slot.as_u64()))
        };
        if !experiment && owner.is_none() {
            recorder.record_summary_eviction("pq.operation_admitted");
            return None;
        }
        let sequence = if experiment {
            recorder.reference()
        } else {
            duty::sequence(&duty::proposal_key(slot.as_u64()))?
        };
        Plan::new(
            if experiment {
                Mode::Experiment
            } else {
                Mode::Production
            },
            json!({
                "kind":"merge","purpose":if owner.is_some(){"proposal_preparation"}else{"reusable_preparation"},
                "proposal_slot":slot.as_u64(),"vote_slots":vote_slots,"sequence":sequence,"attempt_index":1,
                "input_proofs":0,"raw_signatures":0,"input_messages":1
            }),
            owner,
        )
    }
}
