use crate::{BeaconChain, BeaconChainTypes};
use slog::{debug, error};
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;

/// At 12s slot times, the means that the payload preparation routine will run 4s before the start
/// of each slot (`12 / 3 = 4`).
pub const VALIDATOR_REGISTRATION_LOOKAHEAD_FACTOR: u32 = 3;

/// Spawns a routine which ensures connected builders are provided advance notice of any block producers.
///
/// This routine will run once per slot, at `slot_duration / VALIDATOR_REGISTRATION_LOOKAHEAD_FACTOR`
/// before the start of each slot.
///
/// The service will not be started if there are no connected builders.
pub fn start_validator_registration_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    //TODO(sean): change this to check whether we have connected builders
    if chain.execution_layer.is_some() {
        executor.clone().spawn(
            async move { validator_registration_service(executor, chain).await },
            "validator_registration_service",
        );
    }
}

/// Loop indefinitely, calling `BeaconChain::validator_registration_async` at an interval.
async fn validator_registration_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    let slot_duration = chain.slot_clock.slot_duration();

    loop {
        match chain.slot_clock.duration_to_next_slot() {
            Some(duration) => {
                let additional_delay = slot_duration
                    - chain.slot_clock.slot_duration() / VALIDATOR_REGISTRATION_LOOKAHEAD_FACTOR;
                sleep(duration + additional_delay).await;

                debug!(
                    chain.log,
                    "Validator registration routine firing";
                );

                let inner_chain = chain.clone();
                executor.spawn(
                    async move {
                        //TODO(sean): query connected builders here
                    },
                    "validator_registration_update",
                );

                continue;
            }
            None => {
                error!(chain.log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                sleep(slot_duration).await;
                continue;
            }
        };
    }
}
