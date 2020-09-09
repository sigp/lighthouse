use crate::Slasher;
use environment::TaskExecutor;
use slog::{debug, error, info, trace};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::stream::StreamExt;
use tokio::time::{interval_at, Duration, Instant};
use types::EthSpec;

#[derive(Debug)]
pub struct SlasherServer;

impl SlasherServer {
    pub fn run<E: EthSpec, C: SlotClock + 'static>(
        slasher: Arc<Slasher<E>>,
        slot_clock: C,
        executor: &TaskExecutor,
    ) {
        info!(slasher.log, "Starting slasher to detect misbehaviour");
        let sub_executor = executor.clone();
        executor.spawn(
            async move {
                // FIXME(sproul): read slot time from config, align to some fraction of each slot
                // FIXME(sproul): queue updates, don't run them in parallel
                let slot_clock = Arc::new(slot_clock);
                let mut interval = interval_at(Instant::now(), Duration::from_secs(12));
                while interval.next().await.is_some() {
                    let slot_clock = slot_clock.clone();
                    let slasher = slasher.clone();
                    sub_executor.spawn_blocking(
                        move || {
                            if let Some(current_slot) = slot_clock.now() {
                                let t = Instant::now();
                                let current_epoch = current_slot.epoch(E::slots_per_epoch());
                                let (num_validator_chunks, num_attestations) =
                                    slasher.attestation_queue.stats();
                                if let Err(e) = slasher.process_attestations(current_epoch) {
                                    error!(
                                        slasher.log,
                                        "Error during scheduled slasher processing";
                                        "error" => format!("{:?}", e)
                                    );
                                }
                                debug!(
                                    slasher.log,
                                    "Completed slasher update";
                                    "time_taken" => format!("{}ms", t.elapsed().as_millis()),
                                    "num_attestations" => num_attestations,
                                    "num_validator_chunks" => num_validator_chunks,
                                );
                            } else {
                                trace!(
                                    slasher.log,
                                    "Slasher has nothing to do: we are pre-genesis"
                                );
                            }
                        },
                        "slasher_server_process_attestations",
                    );
                }
            },
            "slasher_server",
        );
    }
}
