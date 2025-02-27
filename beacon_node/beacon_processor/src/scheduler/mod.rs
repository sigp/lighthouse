use std::task::Poll;

use futures::stream::Stream;
use futures::StreamExt;
use slog::{crit, debug, trace, warn};
use std::pin::Pin;
use std::task::Context;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use types::EthSpec;
use work_reprocessing_queue::ReadyWork;

use crate::{metrics, QueuedBackfillBatch, ReprocessQueueMessage, WorkEvent, WORKER_FREED};
use crate::{BeaconProcessor, BlockingOrAsync, SendOnDrop, TaskSpawner, Work};

mod earliest_deadline_scheduler;
pub mod interface;
mod priority_scheduler;
pub mod work_reprocessing_queue;

/// Unifies all the messages processed by the `BeaconProcessor`.
enum InboundEvent<E: EthSpec> {
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
struct InboundEvents<E: EthSpec> {
    /// Used by workers when they finish a task.
    idle_rx: mpsc::Receiver<()>,
    /// Used by upstream processes to send new work to the `BeaconProcessor`.
    event_rx: mpsc::Receiver<WorkEvent<E>>,
    ready_work_rx: mpsc::Receiver<ReadyWork>,
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

pub enum NextWorkEvent<E: EthSpec> {
    WorkEvent(Option<WorkEvent<E>>),
    Continue,
    Break,
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
                                    beacon_processor.log,
                                    "Unable to queue backfill work event. Will try to process now.";
                                    "error" => %e
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
                                                    beacon_processor.log,
                                                    "Unexpected queue message type";
                                                    "message_type" => other.as_ref()
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
                debug!(
                    beacon_processor.log,
                    "Gossip processor stopped";
                    "msg" => "stream ended"
                );
                NextWorkEvent::Break
            }
        }
    }
}

/// Spawns a blocking worker thread to process some `Work`.
///
/// Sends an message on `idle_tx` when the work is complete and the task is stopping.
pub fn spawn_worker<E: EthSpec>(
    beacon_processor: &mut BeaconProcessor<E>,
    idle_tx: Sender<()>,
    work: Work<E>,
) {
    let work_id = work.str_id();
    let worker_timer = metrics::start_timer_vec(&metrics::BEACON_PROCESSOR_WORKER_TIME, &[work_id]);
    metrics::inc_counter(&metrics::BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL);
    metrics::inc_counter_vec(
        &metrics::BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT,
        &[work.str_id()],
    );

    // Wrap the `idle_tx` in a struct that will fire the idle message whenever it is dropped.
    //
    // This helps ensure that the worker is always freed in the case of an early exit or panic.
    // As such, this instantiation should happen as early in the function as possible.
    let send_idle_on_drop = SendOnDrop {
        tx: idle_tx,
        _worker_timer: worker_timer,
        log: beacon_processor.log.clone(),
    };

    let worker_id = beacon_processor.current_workers;
    beacon_processor.current_workers = beacon_processor.current_workers.saturating_add(1);

    let executor = beacon_processor.executor.clone();

    trace!(
        beacon_processor.log,
        "Spawning beacon processor worker";
        "work" => work_id,
        "worker" => worker_id,
    );

    let task_spawner = TaskSpawner {
        executor,
        send_idle_on_drop,
    };

    println!("spawing work {:?}", work);

    match work {
        Work::GossipAttestation {
            attestation,
            process_individual,
            process_batch: _,
        } => task_spawner.spawn_blocking(move || {
            process_individual(*attestation);
        }),
        Work::GossipAttestationToConvert {
            attestation,
            process_individual,
        } => task_spawner.spawn_blocking(move || {
            process_individual(*attestation);
        }),
        Work::GossipAttestationBatch {
            attestations,
            process_batch,
        } => task_spawner.spawn_blocking(move || {
            process_batch(attestations);
        }),
        Work::GossipAggregate {
            aggregate,
            process_individual,
            process_batch: _,
        } => task_spawner.spawn_blocking(move || {
            process_individual(*aggregate);
        }),
        Work::GossipAggregateBatch {
            aggregates,
            process_batch,
        } => task_spawner.spawn_blocking(move || {
            process_batch(aggregates);
        }),
        Work::ChainSegment(process_fn) => task_spawner.spawn_async(async move {
            process_fn.await;
        }),
        Work::UnknownBlockAttestation { process_fn }
        | Work::UnknownBlockAggregate { process_fn }
        | Work::UnknownLightClientOptimisticUpdate { process_fn, .. }
        | Work::UnknownBlockSamplingRequest { process_fn } => {
            task_spawner.spawn_blocking(process_fn)
        }
        Work::DelayedImportBlock {
            beacon_block_slot: _,
            beacon_block_root: _,
            process_fn,
        } => task_spawner.spawn_async(process_fn),
        Work::RpcBlock { process_fn }
        | Work::RpcCanonicalBlock { process_fn }
        | Work::RpcBlobs { process_fn }
        | Work::RpcCustodyColumn(process_fn)
        | Work::RpcVerifyDataColumn(process_fn)
        | Work::SamplingResult(process_fn) => task_spawner.spawn_async(process_fn),
        Work::IgnoredRpcBlock { process_fn } => task_spawner.spawn_blocking(process_fn),
        Work::GossipBlock(work)
        | Work::GossipCanonicalBlock(work)
        | Work::GossipBlobSidecar(work)
        | Work::GossipDataColumnSidecar(work) => task_spawner.spawn_async(async move {
            work.await;
        }),
        Work::BlobsByRangeRequest(process_fn)
        | Work::BlobsByRootsRequest(process_fn)
        | Work::DataColumnsByRootsRequest(process_fn)
        | Work::DataColumnsByRangeRequest(process_fn) => task_spawner.spawn_blocking(process_fn),
        Work::BlocksByRangeRequest(work) | Work::BlocksByRootsRequest(work) => {
            task_spawner.spawn_async(work)
        }
        Work::ChainSegmentBackfill(process_fn) => task_spawner.spawn_async(process_fn),
        Work::ApiRequestP0(process_fn) | Work::ApiRequestP1(process_fn) => match process_fn {
            BlockingOrAsync::Blocking(process_fn) => task_spawner.spawn_blocking(process_fn),
            BlockingOrAsync::Async(process_fn) => task_spawner.spawn_async(process_fn),
        },
        Work::GossipVoluntaryExit(process_fn)
        | Work::GossipProposerSlashing(process_fn)
        | Work::GossipAttesterSlashing(process_fn)
        | Work::GossipSyncSignature(process_fn)
        | Work::GossipSyncContribution(process_fn)
        | Work::GossipLightClientFinalityUpdate(process_fn)
        | Work::GossipLightClientOptimisticUpdate(process_fn)
        | Work::Status(process_fn)
        | Work::GossipBlsToExecutionChange(process_fn)
        | Work::LightClientBootstrapRequest(process_fn)
        | Work::LightClientOptimisticUpdateRequest(process_fn)
        | Work::LightClientFinalityUpdateRequest(process_fn)
        | Work::LightClientUpdatesByRangeRequest(process_fn) => {
            task_spawner.spawn_blocking(process_fn)
        }
        Work::Reprocess(_) => {}
    };
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
