use std::{sync::Arc, time::Duration};

use crate::{scheduler::InboundEvents, ReprocessQueueMessage};
use earliest_deadline_queue::{QueueItem, WorkQueue};
use slot_clock::SlotClock;
use tokio::sync::mpsc::{self, Sender};
use tracing::{error, trace, warn};
use types::EthSpec;

use crate::{
    metrics, BeaconProcessor, Work, WorkEvent, WorkType, MAX_IDLE_QUEUE_LEN, NOTHING_TO_DO,
};

use super::{
    spawn_worker,
    work_reprocessing_queue::{spawn_reprocess_scheduler, ReadyWork},
    worker_journal, NextWorkEvent,
};

mod earliest_deadline_queue;

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "earliest_deadline_first_scheduler";

pub struct Scheduler<E: EthSpec, S: SlotClock> {
    beacon_processor: BeaconProcessor<E>,
    work_queue: WorkQueue<QueueItem<E, S>>,
}

impl<E: EthSpec, S: SlotClock + 'static> Scheduler<E, S> {
    pub fn new(beacon_processor: BeaconProcessor<E>) -> Self {
        let work_queue = WorkQueue::new();
        Scheduler {
            beacon_processor,
            work_queue,
        }
    }

    pub fn run(
        mut self,
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        work_journal_tx: Option<Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
    ) -> Result<(), String> {
        let (idle_tx, idle_rx) = mpsc::channel::<()>(MAX_IDLE_QUEUE_LEN);

        let (ready_work_tx, ready_work_rx) =
            mpsc::channel::<ReadyWork>(self.beacon_processor.config.max_scheduled_work_queue_len);

        let (reprocess_work_tx, reprocess_work_rx) = mpsc::channel::<ReprocessQueueMessage>(
            self.beacon_processor.config.max_scheduled_work_queue_len,
        );

        let executor = self.beacon_processor.executor.clone();

        let mut inbound_events = InboundEvents {
            idle_rx,
            event_rx,
            ready_work_rx,
        };

        spawn_reprocess_scheduler(
            ready_work_tx,
            reprocess_work_rx,
            &self.beacon_processor.executor,
            Arc::new(slot_clock.clone()),
            maximum_gossip_clock_disparity,
        )?;

        let manager_future = async move {
            loop {
                let work_event = match inbound_events
                    .next_work_event(&reprocess_work_tx, &mut self.beacon_processor)
                    .await
                {
                    NextWorkEvent::WorkEvent(work_event) => work_event,
                    NextWorkEvent::Continue => continue,
                    NextWorkEvent::Break => break,
                };

                let can_spawn = self.beacon_processor.current_workers
                    < self.beacon_processor.config.max_workers;

                worker_journal(&work_event, &work_journal_tx);
                let drop_during_sync = work_event
                    .as_ref()
                    .is_some_and(|event| event.drop_during_sync);

                let modified_queue_id = match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        if let Some(queue_item) = self.work_queue.pop() {
                            self.process_or_queue_item(
                                &reprocess_work_tx,
                                &idle_tx,
                                queue_item,
                                can_spawn,
                            )
                        } else {
                            // Let the journal know that a worker is freed and there's nothing else
                            // for it to do.
                            if let Some(work_journal_tx) = &work_journal_tx {
                                // We don't care if this message was successfully sent, we only use the journal
                                // during testing.
                                let _ = work_journal_tx.try_send(NOTHING_TO_DO);
                            }
                            None
                        }
                    }
                    // There is no new work event and we are unable to spawn a new worker.
                    //
                    // I cannot see any good reason why this would happen.
                    None => {
                        warn!(
                            msg = "no new work and cannot spawn worker",
                            "Unexpected gossip processor condition"
                        );
                        None
                    }
                    // The chain is syncing and this event should be dropped during sync.
                    Some(work_event)
                        if self
                            .beacon_processor
                            .network_globals
                            .sync_state
                            .read()
                            .is_syncing()
                            && drop_during_sync =>
                    {
                        let work_id = work_event.work.str_id();
                        metrics::inc_counter_vec(
                            &metrics::BEACON_PROCESSOR_WORK_EVENTS_IGNORED_COUNT,
                            &[work_id],
                        );
                        trace!(
                            msg = "chain is syncing",
                            work_id,
                            "Gossip processor skipping work",
                        );
                        None
                    }
                    // There is a new work event and the chain is not syncing. Process it or queue
                    // it.
                    Some(work_event) => {
                        if let Some(queue_item) = QueueItem::new(work_event, &slot_clock) {
                            self.process_or_queue_item(
                                &reprocess_work_tx,
                                &idle_tx,
                                queue_item,
                                can_spawn,
                            )
                        } else {
                            None
                        }
                    }
                };

                self.update_metrics(modified_queue_id);
            }
        };

        // Spawn on the core executor.
        executor.spawn(manager_future, MANAGER_TASK_NAME);

        Ok(())
    }

    fn update_metrics(&mut self, modified_queue_id: Option<WorkType>) {
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_WORKERS_ACTIVE_TOTAL,
            self.beacon_processor.current_workers as i64,
        );

        if let Some(modified_queue_id) = modified_queue_id {
            metrics::observe_vec(
                &metrics::BEACON_PROCESSOR_QUEUE_LENGTH,
                &[modified_queue_id.into()],
                self.work_queue.len() as f64,
            );
        }
    }

    pub fn process_or_queue_item(
        &mut self,
        reprocess_work_tx: &Sender<ReprocessQueueMessage>,
        idle_tx: &Sender<()>,
        queue_item: QueueItem<E, S>,
        can_spawn: bool,
    ) -> Option<WorkType> {
        let work_type = queue_item.work_event.work_type();

        let workers_available =
            self.beacon_processor.config.max_workers - self.beacon_processor.current_workers;

        match queue_item.work_event.work {
            Work::Reprocess(work_event) => {
                if let Err(e) = reprocess_work_tx.try_send(work_event) {
                    error!(
                        error = %e,
                        "Failed to reprocess work event",
                    )
                }
            }
            _ if can_spawn => {
                if queue_item.work_event.work.is_priority_work() || workers_available > 1 {
                    spawn_worker(
                        &mut self.beacon_processor,
                        idle_tx.clone(),
                        queue_item.work_event.work,
                    )
                } else {
                    self.work_queue.insert(queue_item);
                }
            }
            _ => {
                self.work_queue.insert(queue_item);
            }
        }

        Some(work_type)
    }
}
