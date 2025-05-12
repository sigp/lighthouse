use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, StreamExt};
use logging::crit;
use tokio::sync::mpsc::{self, error::TrySendError, Sender};
use tracing::{debug, warn};
use types::EthSpec;
use work_reprocessing_queue::{QueuedBackfillBatch, ReadyWork, ReprocessQueueMessage};

use crate::{BeaconProcessor, WorkEvent, WORKER_FREED};

pub mod work_queue;
pub mod work_reprocessing_queue;

pub enum NextWorkEvent<E: EthSpec> {
    WorkEvent(Option<WorkEvent<E>>),
    Continue,
    Break,
}

/// Unifies all the messages processed by the `BeaconProcessor`.
pub enum InboundEvent<E: EthSpec> {
    /// A worker has completed a task and is free.
    WorkerIdle,
    /// There is new work to be done.
    WorkEvent(WorkEvent<E>),
    /// A work event that was queued for re-processing has become ready.
    ReprocessingWork(WorkEvent<E>),
}

/// Combines the various incoming event streams for the `BeaconProcessor` into a single stream.
///
/// This struct has a similar purpose to `tokio::select!`, however it allows for more fine-grained
/// control (specifically in the ordering of event processing).
pub struct InboundEvents<E: EthSpec> {
    /// Used by workers when they finish a task.
    pub idle_rx: mpsc::Receiver<()>,
    /// Used by upstream processes to send new work to the `BeaconProcessor`.
    pub event_rx: mpsc::Receiver<WorkEvent<E>>,
    /// Used internally for queuing work ready to be re-processed.
    pub ready_work_rx: mpsc::Receiver<ReadyWork>,
}

impl<E: EthSpec> Stream for InboundEvents<E> {
    type Item = InboundEvent<E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Always check for idle workers before anything else. This allows us to ensure that a big
        // stream of new events doesn't suppress the processing of existing events.
        match self.idle_rx.poll_recv(cx) {
            Poll::Ready(Some(())) => {
                return Poll::Ready(Some(InboundEvent::WorkerIdle));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        // Poll for delayed blocks before polling for new work. It might be the case that a delayed
        // block is required to successfully process some new work.
        match self.ready_work_rx.poll_recv(cx) {
            Poll::Ready(Some(ready_work)) => {
                return Poll::Ready(Some(InboundEvent::ReprocessingWork(ready_work.into())));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        match self.event_rx.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                return Poll::Ready(Some(InboundEvent::WorkEvent(event)));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        Poll::Pending
    }
}

impl<E: EthSpec> InboundEvents<E> {
    pub async fn next_work_event(
        &mut self,
        reprocess_work_tx: &Sender<ReprocessQueueMessage>,
        beacon_processor: &mut BeaconProcessor<E>,
    ) -> NextWorkEvent<E> {
        match self.next().await {
            Some(InboundEvent::WorkerIdle) => {
                beacon_processor.current_workers =
                    beacon_processor.current_workers.saturating_sub(1);
                NextWorkEvent::WorkEvent(None)
            }
            Some(InboundEvent::WorkEvent(event))
                if beacon_processor.config.enable_backfill_rate_limiting =>
            {
                match QueuedBackfillBatch::try_from(event) {
                    Ok(backfill_batch) => {
                        match reprocess_work_tx
                            .try_send(ReprocessQueueMessage::BackfillSync(backfill_batch))
                        {
                            Err(e) => {
                                warn!(
                                    error = ?e,
                                    "Unable to queue backfill work event. Will try to process now."
                                );
                                match e {
                                    TrySendError::Full(reprocess_queue_message)
                                    | TrySendError::Closed(reprocess_queue_message) => {
                                        match reprocess_queue_message {
                                            ReprocessQueueMessage::BackfillSync(backfill_batch) => {
                                                NextWorkEvent::WorkEvent(Some(
                                                    backfill_batch.into(),
                                                ))
                                            }
                                            other => {
                                                crit!(
                                                    message_type = other.as_ref(),
                                                    "Unexpected queue message type"
                                                );
                                                // This is an unhandled exception, drop the message.
                                                NextWorkEvent::Continue
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(..) => {
                                // backfill work sent to "reprocessing" queue. Process the next event.
                                NextWorkEvent::Continue
                            }
                        }
                    }
                    Err(event) => NextWorkEvent::WorkEvent(Some(event)),
                }
            }
            Some(InboundEvent::WorkEvent(event)) | Some(InboundEvent::ReprocessingWork(event)) => {
                NextWorkEvent::WorkEvent(Some(event))
            }
            None => {
                debug!(msg = "stream ended", "Gossip processor stopped",);
                NextWorkEvent::Break
            }
        }
    }
}

pub fn worker_journal<E: EthSpec>(
    work_event: &Option<WorkEvent<E>>,
    work_journal_tx: &Option<Sender<&'static str>>,
) {
    if let Some(work_journal_tx) = work_journal_tx {
        let id = work_event
            .as_ref()
            .map(|event| event.work.str_id())
            .unwrap_or(WORKER_FREED);

        // We don't care if this message was successfully sent, we only use the journal
        // during testing. We also ignore reprocess messages to ensure our test cases can pass.
        if id != "reprocess" {
            let _ = work_journal_tx.try_send(id);
        }
    }
}
