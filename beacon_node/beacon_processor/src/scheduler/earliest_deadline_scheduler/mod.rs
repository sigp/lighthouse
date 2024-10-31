use std::{sync::Arc, time::Duration};

use crate::{scheduler::InboundEvents, QueuedBackfillBatch, ReprocessQueueMessage};
use earliest_deadline_queue::{QueueItem, WorkQueue};
use futures::stream::StreamExt;
use slog::{crit, debug, error, trace, warn};
use slot_clock::SlotClock;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{self, Sender};
use types::EthSpec;

use crate::{
    metrics, BeaconProcessor, Work, WorkEvent, WorkType, MAX_IDLE_QUEUE_LEN, NOTHING_TO_DO,
};

use super::{
    spawn_worker,
    work_reprocessing_queue::{spawn_reprocess_scheduler, ReadyWork},
    worker_journal, InboundEvent,
};

mod earliest_deadline_queue;

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "earliest_deadline_first_scheduler";

pub struct Scheduler<E: EthSpec, S: SlotClock> {
    beacon_processor: BeaconProcessor<E>,
    work_queue: WorkQueue<E, S>,
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
            self.beacon_processor.log.clone(),
            maximum_gossip_clock_disparity,
        )?;

        let manager_future = async move {
            loop {
                let work_event = match inbound_events.next().await {
                    Some(InboundEvent::WorkerIdle) => {
                        self.beacon_processor.current_workers =
                            self.beacon_processor.current_workers.saturating_sub(1);
                        None
                    }
                    Some(InboundEvent::WorkEvent(event))
                        if self.beacon_processor.config.enable_backfill_rate_limiting =>
                    {
                        match QueuedBackfillBatch::try_from(event) {
                            Ok(backfill_batch) => {
                                match reprocess_work_tx
                                    .try_send(ReprocessQueueMessage::BackfillSync(backfill_batch))
                                {
                                    Err(e) => {
                                        warn!(
                                            self.beacon_processor.log,
                                            "Unable to queue backfill work event. Will try to process now.";
                                            "error" => %e
                                        );
                                        match e {
                                            TrySendError::Full(reprocess_queue_message)
                                            | TrySendError::Closed(reprocess_queue_message) => {
                                                match reprocess_queue_message {
                                                    ReprocessQueueMessage::BackfillSync(
                                                        backfill_batch,
                                                    ) => Some(backfill_batch.into()),
                                                    other => {
                                                        crit!(
                                                            self.beacon_processor.log,
                                                            "Unexpected queue message type";
                                                            "message_type" => other.as_ref()
                                                        );
                                                        // This is an unhandled exception, drop the message.
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Ok(..) => {
                                        // backfill work sent to "reprocessing" queue. Process the next event.
                                        continue;
                                    }
                                }
                            }
                            Err(event) => Some(event),
                        }
                    }
                    Some(InboundEvent::WorkEvent(event))
                    | Some(InboundEvent::ReprocessingWork(event)) => Some(event),
                    None => {
                        debug!(
                            self.beacon_processor.log,
                            "Gossip processor stopped";
                            "msg" => "stream ended"
                        );
                        break;
                    }
                };

                let can_spawn = self.beacon_processor.current_workers
                    < self.beacon_processor.config.max_workers;

                worker_journal(&work_event, &work_journal_tx);
                let drop_during_sync = work_event
                    .as_ref()
                    .map_or(false, |event| event.drop_during_sync);

                let modified_queue_id = match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        let work_event = self.earliest_deadline_first_scheduler();
                        if let Some(work_event) = work_event {
                            let work_type = work_event.to_type();
                            println!("weve spawned a worker here");
                            spawn_worker(&mut self.beacon_processor, idle_tx.clone(), work_event);
                            Some(work_type)
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
                            self.beacon_processor.log,
                            "Unexpected gossip processor condition";
                            "msg" => "no new work and cannot spawn worker"
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
                            self.beacon_processor.log,
                            "Gossip processor skipping work";
                            "msg" => "chain is syncing",
                            "work_id" => work_id
                        );
                        None
                    }
                    // There is a new work event and the chain is not syncing. Process it or queue
                    // it.
                    Some(WorkEvent { work, .. }) => {
                        println!("work: {:?}", work);
                        self.process_or_queue_work_event(
                            &reprocess_work_tx,
                            idle_tx.clone(),
                            work,
                            &slot_clock,
                            can_spawn,
                        )
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
        // TODO check if is_full?
    }

    fn earliest_deadline_first_scheduler(&mut self) -> Option<Work<E>> {
        let queue_item = self.work_queue.pop();

        if let Some(queue_item) = queue_item {
            Some(queue_item.work_event.work)
        } else {
            None
        }
    }

    pub fn process_or_queue_work_event(
        &mut self,
        reprocess_work_tx: &Sender<ReprocessQueueMessage>,
        idle_tx: Sender<()>,
        work: Work<E>,
        slot_clock: &S,
        can_spawn: bool,
    ) -> Option<WorkType> {
        let work_type = work.to_type();

        match work {
            Work::Reprocess(work_event) => {
                if let Err(e) = reprocess_work_tx.try_send(work_event) {
                    error!(
                        self.beacon_processor.log,
                        "Failed to reprocess work event";
                        "error" => %e
                    )
                }
            }
            _ if can_spawn => {
                println!("spawning");
                spawn_worker(&mut self.beacon_processor, idle_tx.clone(), work)
            }
            _ => {
                let Some(queue_item) = QueueItem::new(work, slot_clock) else {
                    return None;
                };
                println!("queue");
                self.work_queue.insert(queue_item);
            }
        }

        Some(work_type)
    }
}
