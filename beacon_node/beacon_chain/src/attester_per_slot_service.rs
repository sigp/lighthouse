use crate::{BeaconChain, BeaconChainTypes};
use slog::{debug, error};
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use types::RelativeEpoch;

/// Spawns a routine which produces an unaggregated attestation at every slot.
///
/// This routine will run once per slot
pub fn start_attester_per_slot_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    // TODO: AI(joel) Only run the service if validator monitor is enabled
    // Paul has made a refacto of that bit in another PR, I will rebase
    // once it's merged
    executor.clone().spawn(
        async move { attester_per_slot_service(executor, chain).await },
        "attester_per_slot_service",
    );
}

/// Loop indefinitely, calling `BeaconChain::produce_unaggregated_attestation` every 4s into each slot.
async fn attester_per_slot_service<T: BeaconChainTypes>(
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
                            // Get the committee cache for the current slot
                            if let Ok(committee_cache) =
                                state.committee_cache(RelativeEpoch::Current)
                            {
                                let committee_count = committee_cache.committees_per_slot();

                                // Produce an unaggregated attestation for each committee
                                for index in 0..committee_count {
                                    if let Some(beacon_committee) =
                                        committee_cache.get_beacon_committee(current_slot, index)
                                    {
                                        // Store the unaggregated attestation in the validator monitor
                                        // or log an error if it fails
                                        match inner_chain.produce_unaggregated_attestation(
                                            current_slot,
                                            beacon_committee.index,
                                        ) {
                                            Ok(unaggregated_attestion) => {
                                                debug!(
                                                inner_chain.log,
                                                "Produce unaggregated attestation";
                                                "slot" => current_slot,
                                                "committee_index" => beacon_committee.index,
                                                "committee_len" => beacon_committee.committee.len(),
                                                "attestation" => ?unaggregated_attestion
                                                );

                                                inner_chain
                                                    .validator_monitor
                                                    .write()
                                                    .set_unaggregated_attestation(
                                                        unaggregated_attestion,
                                                    );
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
                    },
                    "attester_per_slot_service",
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
