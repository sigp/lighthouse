use crate::metrics::{self, SLASHER_DATABASE_SIZE, SLASHER_RUN_TIME};
use crate::Slasher;
use directory::size_of_dir;
use slog::{debug, error, info, trace};
use slot_clock::SlotClock;
use std::sync::mpsc::{sync_channel, TrySendError};
use std::sync::Arc;
use task_executor::TaskExecutor;
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
                // NOTE: could align each run to some fixed point in each slot, see:
                // https://github.com/sigp/lighthouse/issues/1861
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
                    let num_attestations = slasher.attestation_queue.len();
                    let num_blocks = slasher.block_queue.len();

                    let batch_timer = metrics::start_timer(&SLASHER_RUN_TIME);
                    if let Err(e) = slasher.process_queued(current_epoch) {
                        error!(
                            slasher.log,
                            "Error during scheduled slasher processing";
                            "epoch" => current_epoch,
                            "error" => format!("{:?}", e)
                        );
                    }
                    drop(batch_timer);

                    // Prune the database, even in the case where batch processing failed.
                    // If the LMDB database is full then pruning could help to free it up.
                    if let Err(e) = slasher.prune_database(current_epoch) {
                        error!(
                            slasher.log,
                            "Error during slasher database pruning";
                            "epoch" => current_epoch,
                            "error" => format!("{:?}", e),
                        );
                        continue;
                    }
                    debug!(
                        slasher.log,
                        "Completed slasher update";
                        "epoch" => current_epoch,
                        "time_taken" => format!("{}ms", t.elapsed().as_millis()),
                        "num_attestations" => num_attestations,
                        "num_blocks" => num_blocks,
                    );

                    let database_size = size_of_dir(&slasher.config().database_path);
                    metrics::set_gauge(&SLASHER_DATABASE_SIZE, database_size as i64);
                }
            },
            "slasher_server_process_queued",
        );
    }
}
