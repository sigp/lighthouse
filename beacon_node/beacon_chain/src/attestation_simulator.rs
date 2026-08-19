use crate::{BeaconChain, BeaconChainTypes};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, warn};
use types::{ChainSpec, EthSpec, Slot};

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

/// Loop indefinitely, calling `BeaconChain::produce_unaggregated_attestation` each slot at the
/// unaggregated attestation deadline.
async fn attestation_simulator_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    let slot_duration = chain.slot_clock.slot_duration();

    loop {
        match chain.slot_clock.now_duration() {
            Some(now_duration) => {
                let (attestation_slot, Some(time_to_deadline)) =
                    time_until_attestation_deadline::<T::EthSpec>(
                        &chain.slot_clock,
                        &chain.spec,
                        now_duration,
                    )
                else {
                    error!("Failed to calculate attestation deadline");
                    sleep(slot_duration).await;
                    continue;
                };
                sleep(time_to_deadline).await;

                debug!("Simulating unagg. attestation production");

                // Run the task in the executor
                let inner_chain = chain.clone();
                executor.spawn(
                    async move {
                        if let Some(slot) = inner_chain.slot_clock.now() && slot == attestation_slot {
                            produce_unaggregated_attestation(inner_chain, attestation_slot);
                        } else {
                            warn!(%attestation_slot, "Missed attestation simulator slot due to lag");
                        }
                    },
                    "attestation_simulator_service",
                );
            }
            None => {
                error!("Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                sleep(slot_duration).await;
            }
        };
    }
}

fn time_until_attestation_deadline<E: EthSpec>(
    slot_clock: &impl SlotClock,
    chain_spec: &ChainSpec,
    now: Duration,
) -> (Slot, Option<Duration>) {
    let attestation_slot = slot_clock
        .slot_of(now)
        .map_or_else(|| slot_clock.genesis_slot(), |slot| slot + 1);
    let duration_to_attestation_deadline = slot_clock
        .start_of(attestation_slot)
        .and_then(|slot_start| {
            slot_start.checked_add(chain_spec.get_attestation_due::<E>(attestation_slot))
        })
        .and_then(|deadline| deadline.checked_sub(now));
    (attestation_slot, duration_to_attestation_deadline)
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
                attestation_source = data.source.root.to_string(),
                attestation_target = data.target.root.to_string(),
                "Produce unagg. attestation"
            );

            chain
                .validator_monitor
                .write()
                .set_unaggregated_attestation(unaggregated_attestation);
        }
        Err(e) => {
            debug!(
                error = ?e,
                "Failed to simulate attestation"
            );
        }
    }
}
