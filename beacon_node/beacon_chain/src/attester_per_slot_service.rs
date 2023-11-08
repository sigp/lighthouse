use crate::{BeaconChain, BeaconChainTypes};
use slog::{debug, error};
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use types::{BeaconState, RelativeEpoch, Slot};

/// Spawns a routine which produces an unaggregated attestation at every slot.
///
/// This routine will run once per slot
pub fn start_attestation_simulator_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    // TODO: AI(joel) Only run the service if validator monitor is enabled
    // Paul has made a refacto of that bit in another PR, I will rebase
    // once it's merged
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
                    "Produce an unaggregated attestation";
                );

                // I am not sure the impact of cloning the state at every epoch yet
                // That's probably the naive solution, I'll reiterate on this later
                let inner_chain = chain.clone();
                let state = inner_chain.head_beacon_state_cloned();

                // Run the task in the executor
                executor.spawn(
                    async move {
                        if let Ok(current_slot) = inner_chain.slot() {
                            produce_unaggregated_attestation(inner_chain, state, current_slot);
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
    inner_chain: Arc<BeaconChain<T>>,
    state: BeaconState<<T as BeaconChainTypes>::EthSpec>,
    current_slot: Slot,
) {
    // Get the committee cache for the current slot
    if let Ok(committee_cache) = state.committee_cache(RelativeEpoch::Current) {
        let committee_count = committee_cache.committees_per_slot();

        // Produce an unaggregated attestation for each committee
        for index in 0..committee_count {
            if let Some(beacon_committee) =
                committee_cache.get_beacon_committee(current_slot, index)
            {
                // Store the unaggregated attestation in the validator monitor for later processing
                match inner_chain
                    .produce_unaggregated_attestation(current_slot, beacon_committee.index)
                {
                    Ok(unaggregated_attestation) => {
                        let data = &unaggregated_attestation.data;
                        debug!(
                        inner_chain.log,
                        "Produce unaggregated attestation";
                        "data.source.root" => data.source.root.to_string(),
                        "data.source.root" => data.target.root.to_string(),
                        );
                        inner_chain
                            .validator_monitor
                            .write()
                            .set_unaggregated_attestation(unaggregated_attestation);
                    }
                    Err(e) => {
                        error!(
                        inner_chain.log,
                        "Produce unaggregated attestation failed";
                        "error" => ?e
                        );
                    }
                }
            } else {
                error!(
                    inner_chain.log,
                    "No beacon committee found";
                    "slot" => current_slot,
                );
            }
        }
    } else {
        error!(
            inner_chain.log,
            "No committee cache found";
            "slot" => current_slot,
        );
    }
}
