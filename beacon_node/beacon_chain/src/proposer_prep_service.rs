use crate::{BeaconChain, BeaconChainTypes};
use slog::{debug, error};
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;

/// Spawns a routine which ensures the EL is provided advance notice of any block producers.
///
/// This routine will run once per slot, at `chain.prepare_payload_lookahead()`
/// before the start of each slot.
///
/// The service will not be started if there is no `execution_layer` on the `chain`.
pub fn start_proposer_prep_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    // Avoid spawning the service if there's no EL, it'll just error anyway.
    if chain.execution_layer.is_some() {
        executor.clone().spawn(
            async move { proposer_prep_service(executor, chain).await },
            "proposer_prep_service",
        );
    }
}

/// Loop indefinitely, calling `BeaconChain::prepare_beacon_proposer_async` at an interval.
async fn proposer_prep_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    let slot_duration = chain.slot_clock.slot_duration();

    loop {
        match chain.slot_clock.duration_to_next_slot() {
            Some(duration) => {
                let additional_delay =
                    slot_duration.saturating_sub(chain.config.prepare_payload_lookahead);
                sleep(duration + additional_delay).await;

                debug!(
                    chain.log,
                    "Proposer prepare routine firing";
                );

                let inner_chain = chain.clone();
                executor.spawn(
                    async move {
                        if let Ok(current_slot) = inner_chain.slot() {
                            if let Err(e) = inner_chain.prepare_beacon_proposer(current_slot).await
                            {
                                error!(
                                    inner_chain.log,
                                    "Proposer prepare routine failed";
                                    "error" => ?e
                                );
                            }
                        } else {
                            debug!(inner_chain.log, "No slot for proposer prepare routine");
                        }
                    },
                    "proposer_prep_update",
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
