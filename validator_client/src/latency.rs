use crate::{http_metrics::metrics, BeaconNodeFallback};
use environment::RuntimeContext;
use slog::debug;
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::time::sleep;
use types::EthSpec;

/// The latency service will run 11/12ths of the way through the slot.
pub const SLOT_DELAY_MULTIPLIER: u32 = 11;
pub const SLOT_DELAY_DENOMINATOR: u32 = 12;

/// Starts a service that periodically checks the latency between the VC and the
/// candidate BNs.
pub fn start_latency_service<T: SlotClock + 'static, E: EthSpec>(
    context: RuntimeContext<E>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
) {
    let log = context.log().clone();

    let future = async move {
        loop {
            let sleep_time = slot_clock
                .duration_to_next_slot()
                .map(|next_slot| {
                    // This is 11/12ths through the next slot. On mainnet this
                    // will happen in the 11th second of each slot, one second
                    // before the next slot.
                    next_slot + (next_slot / SLOT_DELAY_DENOMINATOR) * SLOT_DELAY_MULTIPLIER
                })
                // If we can't read the slot clock, just wait one slot. Running
                // the measurement at a non-exact time is not a big issue.
                .unwrap_or_else(|| slot_clock.slot_duration());

            // Sleep until it's time to perform the measurement.
            sleep(sleep_time).await;

            for measurement in beacon_nodes.measure_latency().await {
                if let Some(latency) = measurement.latency {
                    debug!(
                        log,
                        "Measured BN latency";
                        "node" => &measurement.beacon_node_id,
                        "latency" => latency.as_millis(),
                    );
                    metrics::observe_timer_vec(
                        &metrics::VC_BEACON_NODE_LATENCY,
                        &[&measurement.beacon_node_id],
                        latency,
                    )
                }
            }
        }
    };

    context.executor.spawn(future, "latency");
}
