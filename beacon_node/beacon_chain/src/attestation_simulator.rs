use crate::{BeaconChain, BeaconChainTypes};
use slog::{debug, error};
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use types::{EthSpec, Slot};

/// Don't run the attestation simulator if the head slot is this many epochs
/// behind the wall-clock slot.
const SYNCING_TOLERANCE_EPOCHS: u64 = 2;

/// Spawns a routine which produces an unaggregated attestation at every slot.
///
/// This routine will run once per slot
pub fn start_attestation_simulator_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    executor.clone().spawn(
        async move { attestation_simulator_service(executor, chain).await },
        "attestation_simulator_service",
    );
}

/// Loop indefinitely, calling `BeaconChain::produce_unaggregated_attestation` every 4s into each slot.
async fn attestation_simulator_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    let slot_duration = chain.slot_clock.slot_duration();
    let additional_delay = slot_duration / 3;

    loop {
        match chain.slot_clock.duration_to_next_slot() {
            Some(duration) => {
                sleep(duration + additional_delay).await;

                debug!(
                    chain.log,
                    "Simulating unagg. attestation production";
                );

                // Run the task in the executor
                let inner_chain = chain.clone();
                executor.spawn(
                    async move {
                        if let Ok(current_slot) = inner_chain.slot() {
                            produce_unaggregated_attestation(inner_chain, current_slot);
                        }
                    },
                    "attestation_simulator_service",
                );
            }
            None => {
                error!(chain.log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                sleep(slot_duration).await;
            }
        };
    }
}

pub fn produce_unaggregated_attestation<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    current_slot: Slot,
) {
    // Don't run the attestation simulator when the head slot is far behind the
    // wall-clock slot.
    //
    // This helps prevent the simulator from becoming a burden by computing
    // committees from old states.
    let syncing_tolerance_slots = SYNCING_TOLERANCE_EPOCHS * T::EthSpec::slots_per_epoch();
    if chain.best_slot() + syncing_tolerance_slots < current_slot {
        return;
    }

    // Since attestations for different committees are practically identical (apart from the committee index field)
    // Committee 0 is guaranteed to exist. That means there's no need to load the committee.
    let beacon_committee_index = 0;

    // Store the unaggregated attestation in the validator monitor for later processing
    match chain.produce_unaggregated_attestation(current_slot, beacon_committee_index) {
        Ok(unaggregated_attestation) => {
            let data = unaggregated_attestation.data();

            debug!(
                chain.log,
                "Produce unagg. attestation";
                "attestation_source" => data.source.root.to_string(),
                "attestation_target" => data.target.root.to_string(),
            );

            chain
                .validator_monitor
                .write()
                .set_unaggregated_attestation(unaggregated_attestation);
        }
        Err(e) => {
            debug!(
                chain.log,
                "Failed to simulate attestation";
                "error" => ?e
            );
        }
    }
}
