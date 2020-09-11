use crate::Slasher;
use environment::TaskExecutor;
use slog::{debug, error, info, trace};
use slot_clock::SlotClock;
use std::sync::mpsc::{sync_channel, TrySendError};
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

        // Buffer just a single message in the channel. If the receiver is still processing, we
        // don't need to burden them with more work (we can wait).
        let (sender, receiver) = sync_channel(1);
        let log = slasher.log.clone();
        let update_period = slasher.config().update_period;

        executor.spawn(
            async move {
                // FIXME(sproul): read slot time from config, align to some fraction of each slot
                let slot_clock = Arc::new(slot_clock);
                let mut interval = interval_at(Instant::now(), Duration::from_secs(update_period));
                while interval.next().await.is_some() {
                    if let Some(current_slot) = slot_clock.clone().now() {
                        let current_epoch = current_slot.epoch(E::slots_per_epoch());
                        if let Err(TrySendError::Disconnected(_)) = sender.try_send(current_epoch) {
                            break;
                        }
                    } else {
                        trace!(log, "Slasher has nothing to do: we are pre-genesis");
                    }
                }
            },
            "slasher_server",
        );

        executor.spawn_blocking(
            move || {
                while let Ok(current_epoch) = receiver.recv() {
                    let t = Instant::now();
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
                }
            },
            "slasher_server_process_attestations",
        );
    }
}
