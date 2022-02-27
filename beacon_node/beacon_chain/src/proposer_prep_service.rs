use crate::{BeaconChain, BeaconChainTypes};
use slog::error;
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;

pub const PAYLOAD_PREPARATION_LOOKAHEAD_FACTOR: u32 = 3;

pub fn start_proposer_prep_service<T: BeaconChainTypes>(
    executor: &TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    executor.spawn(
        async move { proposer_prep_service(chain).await },
        "proposer_prep_service",
    );
}

async fn proposer_prep_service<T: BeaconChainTypes>(chain: Arc<BeaconChain<T>>) {
    let slot_duration = chain.slot_clock.slot_duration();

    loop {
        match chain.slot_clock.duration_to_next_slot() {
            Some(duration) => {
                let additional_delay = slot_duration
                    - chain.slot_clock.slot_duration() / PAYLOAD_PREPARATION_LOOKAHEAD_FACTOR;
                sleep(duration + additional_delay).await;

                if let Err(e) = chain.prepare_beacon_proposer().await {
                    error!(
                        chain.log,
                        "Proposer prepare routine failed";
                        "error" => ?e
                    );
                }

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
