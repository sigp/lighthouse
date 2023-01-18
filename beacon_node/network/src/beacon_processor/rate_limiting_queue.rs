use slog::{debug, error, Logger};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

use beacon_chain::BeaconChainTypes;
use slot_clock::SlotClock;
use task_executor::TaskExecutor;

use crate::beacon_processor::{WorkEvent, MAX_SCHEDULED_WORK_QUEUE_LEN};

pub enum ScheduledWork<T: BeaconChainTypes> {
    BackfillSync(WorkEvent<T>),
}

pub fn spawn_rate_limiting_scheduler<T: BeaconChainTypes>(
    schedule_work_tx: Sender<ScheduledWork<T>>,
    executor: &TaskExecutor,
    slot_clock: T::SlotClock,
    log: Logger,
) -> Sender<WorkEvent<T>> {
    let (work_rate_limiting_tx, mut work_rate_limiting_rx) =
        mpsc::channel::<WorkEvent<T>>(MAX_SCHEDULED_WORK_QUEUE_LEN);

    // FIXME(jimmy): this impl is not as generic/flexible as the module name suggested
    executor.spawn(
        async move {
            loop {
                match work_rate_limiting_rx.recv().await {
                    Some(event) => {
                        debug!(
                            log,
                            "Sending scheduled backfill work event to BeaconProcessor"
                        );
                        if schedule_work_tx
                            .try_send(ScheduledWork::BackfillSync(event))
                            .is_err()
                        {
                            error!(
                                log,
                                "Failed to send scheduled backfill work event";
                            );
                        }
                    }
                    None => {}
                }

                let slot_duration = slot_clock.slot_duration();

                if let Some(duration_to_next_slot) = slot_clock.duration_to_next_slot() {
                    // FIXME(jimmy): Fire the work event at 6s, 7s, 10s, after slot start.
                    // this assumes 12s slots, also need to consider different slot times
                    sleep(duration_to_next_slot + (slot_duration / 2)).await;
                } else {
                    // Just sleep for one slot if we are unable to read the system clock, this gives
                    // us an opportunity for the clock to eventually come good.
                    sleep(slot_clock.slot_duration()).await;
                }
                // TODO: finish loop when backfill sync is completed
            }
        },
        "rate_limiting_scheduler",
    );

    work_rate_limiting_tx
}
