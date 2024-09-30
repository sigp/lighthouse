// The priority scheduler has three major facets
// 1. A priority ordering system
// 2. A backfill rate limiting feature
// 3. A retry queue

mod work_queue;
mod work_reprocessing_queue;

use futures::stream::{Stream, StreamExt};
use futures::task::Poll;
use lighthouse_metrics::HistogramTimer;
use slog::error;
use slog::{crit, debug, trace, warn};
use slot_clock::SlotClock;
use std::borrow::BorrowMut;
use std::pin::Pin;
use std::task::Context;
use std::{cmp, marker::PhantomData, sync::Arc, time::Duration};
use tokio::sync::mpsc::{self, error::TrySendError, Receiver, Sender};
use types::{BeaconState, ChainSpec, EthSpec};
use work_queue::{BeaconProcessorQueueLengths, WorkQueues};
use work_reprocessing_queue::{spawn_reprocess_scheduler, ReadyWork};

use crate::{
    metrics, BeaconProcessor, BeaconProcessorConfig, BlockingOrAsync, QueuedBackfillBatch,
    ReprocessQueueMessage, SendOnDrop, TaskSpawner, Work, WorkEvent, WorkType, MAX_IDLE_QUEUE_LEN,
    NOTHING_TO_DO, WORKER_FREED,
};

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
    /// Used internally for queuing work ready to be re-processed.
    reprocess_work_rx: mpsc::Receiver<ReadyWork>,
}

struct OutboundEvents {
    /// Sends tasks to workers.
    idle_tx: mpsc::Sender<()>,
    /// Used internally for queuing work ready to be re-processed.
    reprocess_work_tx: mpsc::Sender<ReadyWork>,
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
        match self.reprocess_work_rx.poll_recv(cx) {
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

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "beacon_processor_manager";

/// The name of the worker tokio tasks.
const WORKER_TASK_NAME: &str = "beacon_processor_worker";

// TODO(beacon-processor) this will be impl specific

// Backend trait inits a channel, a run function
// A channel trait has send_work, reprocess_work etc.
pub struct Scheduler<E: EthSpec, S: SlotClock> {
    beacon_processor: BeaconProcessor<E>,
    inbound_events: InboundEvents<E>,
    outbound_events: OutboundEvents,
    work_queues: WorkQueues<E>,
    phantom_data: PhantomData<S>,
}

impl<E: EthSpec, S: SlotClock + 'static> Scheduler<E, S> {
    pub fn new(
        beacon_processor: BeaconProcessor<E>,
        beacon_state: &BeaconState<E>,
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, String> {
        // Used by workers to communicate that they are finished a task.
        let (idle_tx, idle_rx) = mpsc::channel::<()>(MAX_IDLE_QUEUE_LEN);

        let queue_lengths = BeaconProcessorQueueLengths::from_state(beacon_state, spec)?;

        // Initialize the worker queues.
        let work_queues: WorkQueues<E> = WorkQueues::new(queue_lengths);

        // Channels for sending work to the re-process scheduler (`work_reprocessing_tx`) and to
        // receive them back once they are ready (`ready_work_rx`).
        let (ready_work_tx, ready_work_rx) =
            mpsc::channel::<ReadyWork>(beacon_processor.config.max_scheduled_work_queue_len);

        let (work_reprocessing_tx, reprocess_work_rx) =
            mpsc::channel::<ReprocessQueueMessage>(beacon_processor.config.max_scheduled_work_queue_len);

        let inbound_events = InboundEvents {
            idle_rx,
            event_rx,
            reprocess_work_rx: ready_work_rx,
        };

        let outbound_events = OutboundEvents {
            idle_tx,
            reprocess_work_tx: ready_work_tx
        };

        Self {
            beacon_processor,
            inbound_events,
            outbound_events,
            work_queues,
            phantom_data: PhantomData
        }
    }

    pub fn run(
        mut self,
        work_journal_tx: Option<Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
    ) -> Result<(), String> {
        // Channels for sending work to the re-process scheduler (`work_reprocessing_tx`) and to
        // receive them back once they are ready (`ready_work_rx`).
        let (ready_work_tx, ready_work_rx) =
            mpsc::channel::<ReadyWork>(self.beacon_processor.config.max_scheduled_work_queue_len);

        let (work_reprocessing_tx, work_reprocessing_rx) = mpsc::channel::<ReprocessQueueMessage>(
            self.beacon_processor.config.max_scheduled_work_queue_len,
        );

        // TODO(beacon-processor) reprocess scheduler
        spawn_reprocess_scheduler(
            ready_work_tx,
            work_reprocessing_rx,
            &self.beacon_processor.executor,
            Arc::new(slot_clock),
            self.beacon_processor.log.clone(),
            maximum_gossip_clock_disparity,
        )?;

        let executor = self.beacon_processor.executor.clone();

        let manager_future = async move {
            let idle_tx = self.outbound_events.idle_tx.clone();
            loop {
                let work_event = match self.inbound_events.next().await {
                    Some(InboundEvent::WorkerIdle) => {
                        self.beacon_processor.current_workers = self.beacon_processor.current_workers.saturating_sub(1);
                        None
                    }
                    Some(InboundEvent::WorkEvent(event))
                        if self.beacon_processor.config.enable_backfill_rate_limiting =>
                    {
                        match QueuedBackfillBatch::try_from(event) {
                            Ok(backfill_batch) => {
                                match work_reprocessing_tx
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

                let _event_timer = self.increment_metrics(&work_event);
                self.worker_journal(&work_event, &work_journal_tx);

                let can_spawn = self.beacon_processor.current_workers < self.beacon_processor.config.max_workers;
                let drop_during_sync = work_event
                    .as_ref()
                    .map_or(false, |event| event.drop_during_sync);

                let modified_queue_id = match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        let work_event = self.priority_scheduler(&work_journal_tx);
                        if let Some(work_event) = work_event {
                            let work_type = work_event.to_type();
                            // TODO(beacon-processor) check self.idle_tx
                            self.spawn_worker(work_event);
                            Some(work_type)
                        } else {
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
                        self.process_or_queue_work_event(work, can_spawn)
                    }
                };

                self.update_queue_metrics(modified_queue_id);
            }
        };

        // Spawn on the core executor.
        executor.spawn(manager_future, MANAGER_TASK_NAME);

        Ok(())
    }

    fn priority_scheduler(
        &mut self,
        work_journal_tx: &Option<Sender<&'static str>>,
    ) -> Option<Work<E>> {
        // Check for chain segments first, they're the most efficient way to get
        // blocks into the system.
        let work_event: Option<Work<E>> =
            if let Some(item) = self.work_queues.chain_segment_queue.pop() {
                Some(item)
            // Check sync blocks before gossip blocks, since we've already explicitly
            // requested these blocks.
            } else if let Some(item) = self.work_queues.rpc_block_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.rpc_blob_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.rpc_custody_column_queue.pop() {
                Some(item)
            // TODO(das): decide proper prioritization for sampling columns
            } else if let Some(item) = self.work_queues.rpc_custody_column_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.rpc_verify_data_column_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.sampling_result_queue.pop() {
                Some(item)
            // Check delayed blocks before gossip blocks, the gossip blocks might rely
            // on the delayed ones.
            } else if let Some(item) = self.work_queues.delayed_block_queue.pop() {
                Some(item)
            // Check gossip blocks before gossip attestations, since a block might be
            // required to verify some attestations.
            } else if let Some(item) = self.work_queues.gossip_block_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.gossip_blob_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.gossip_data_column_queue.pop() {
                Some(item)
            // Check the priority 0 API requests after blocks and blobs, but before attestations.
            } else if let Some(item) = self.work_queues.api_request_p0_queue.pop() {
                Some(item)
            // Check the aggregates, *then* the unaggregates since we assume that
            // aggregates are more valuable to local validators and effectively give us
            // more information with less signature verification time.
            } else if self.work_queues.aggregate_queue.len() > 0 {
                let batch_size = cmp::min(
                    self.work_queues.aggregate_queue.len(),
                    self.beacon_processor.config.max_gossip_aggregate_batch_size,
                );

                if batch_size < 2 {
                    // One single aggregate is in the queue, process it individually.
                    self.work_queues.aggregate_queue.pop()
                } else {
                    // Collect two or more aggregates into a batch, so they can take
                    // advantage of batch signature verification.
                    //
                    // Note: this will convert the `Work::GossipAggregate` item into a
                    // `Work::GossipAggregateBatch` item.
                    let mut aggregates = Vec::with_capacity(batch_size);
                    let mut process_batch_opt = None;
                    for _ in 0..batch_size {
                        if let Some(item) = self.work_queues.aggregate_queue.pop() {
                            match item {
                                Work::GossipAggregate {
                                    aggregate,
                                    process_individual: _,
                                    process_batch,
                                } => {
                                    aggregates.push(*aggregate);
                                    if process_batch_opt.is_none() {
                                        process_batch_opt = Some(process_batch);
                                    }
                                }
                                _ => {
                                    error!(
                                        self.beacon_processor.log,
                                        "Invalid item in aggregate queue"
                                    );
                                }
                            }
                        }
                    }

                    if let Some(process_batch) = process_batch_opt {
                        // Process all aggregates with a single worker.
                        Some(Work::GossipAggregateBatch {
                            aggregates,
                            process_batch,
                        })
                    } else {
                        // There is no good reason for this to
                        // happen, it is a serious logic error.
                        // Since we only form batches when multiple
                        // work items exist, we should always have a
                        // work closure at this point.
                        crit!(self.beacon_processor.log, "Missing aggregate work");
                        None
                    }
                }
            // Check the unaggregated attestation queue.
            //
            // Potentially use batching.
            } else if self.work_queues.attestation_queue.len() > 0 {
                let batch_size = cmp::min(
                    self.work_queues.attestation_queue.len(),
                    self.beacon_processor
                        .config
                        .max_gossip_attestation_batch_size,
                );

                if batch_size < 2 {
                    // One single attestation is in the queue, process it individually.
                    self.work_queues.attestation_queue.pop()
                } else {
                    // Collect two or more attestations into a batch, so they can take
                    // advantage of batch signature verification.
                    //
                    // Note: this will convert the `Work::GossipAttestation` item into a
                    // `Work::GossipAttestationBatch` item.
                    let mut attestations = Vec::with_capacity(batch_size);
                    let mut process_batch_opt = None;
                    for _ in 0..batch_size {
                        if let Some(item) = self.work_queues.attestation_queue.pop() {
                            match item {
                                Work::GossipAttestation {
                                    attestation,
                                    process_individual: _,
                                    process_batch,
                                } => {
                                    attestations.push(*attestation);
                                    if process_batch_opt.is_none() {
                                        process_batch_opt = Some(process_batch);
                                    }
                                }
                                _ => error!(
                                    self.beacon_processor.log,
                                    "Invalid item in attestation queue"
                                ),
                            }
                        }
                    }

                    if let Some(process_batch) = process_batch_opt {
                        // Process all attestations with a single worker.
                        Some(Work::GossipAttestationBatch {
                            attestations,
                            process_batch,
                        })
                    } else {
                        // There is no good reason for this to
                        // happen, it is a serious logic error.
                        // Since we only form batches when multiple
                        // work items exist, we should always have a
                        // work closure at this point.
                        crit!(self.beacon_processor.log, "Missing attestations work");
                        None
                    }
                }
            // Check sync committee messages after attestations as their rewards are lesser
            // and they don't influence fork choice.
            } else if let Some(item) = self.work_queues.sync_contribution_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.sync_message_queue.pop() {
                Some(item)
            // Aggregates and unaggregates queued for re-processing are older and we
            // care about fresher ones, so check those first.
            } else if let Some(item) = self.work_queues.unknown_block_aggregate_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.unknown_block_attestation_queue.pop() {
                Some(item)
            // Check RPC methods next. Status messages are needed for sync so
            // prioritize them over syncing requests from other peers (BlocksByRange
            // and BlocksByRoot)
            } else if let Some(item) = self.work_queues.status_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.bbrange_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.bbroots_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.blbrange_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.blbroots_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.dcbroots_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.dcbrange_queue.pop() {
                Some(item)
            // Prioritize sampling requests after block syncing requests
            } else if let Some(item) = self.work_queues.unknown_block_sampling_request_queue.pop() {
                Some(item)
            // Check slashings after all other consensus messages so we prioritize
            // following head.
            //
            // Check attester slashings before proposer slashings since they have the
            // potential to slash multiple validators at once.
            } else if let Some(item) = self.work_queues.gossip_attester_slashing_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.gossip_proposer_slashing_queue.pop() {
                Some(item)
            // Check exits and address changes late since our validators don't get
            // rewards from them.
            } else if let Some(item) = self.work_queues.gossip_voluntary_exit_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.gossip_bls_to_execution_change_queue.pop() {
                Some(item)
            // Check the priority 1 API requests after we've
            // processed all the interesting things from the network
            // and things required for us to stay in good repute
            // with our P2P peers.
            } else if let Some(item) = self.work_queues.api_request_p1_queue.pop() {
                Some(item)
            // Handle backfill sync chain segments.
            } else if let Some(item) = self.work_queues.backfill_chain_segment.pop() {
                Some(item)
            // Handle light client requests.
            } else if let Some(item) = self.work_queues.lc_bootstrap_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.lc_optimistic_update_queue.pop() {
                Some(item)
            } else if let Some(item) = self.work_queues.lc_finality_update_queue.pop() {
                Some(item)
                // This statement should always be the final else statement.
            } else {
                // Let the journal know that a worker is freed and there's nothing else
                // for it to do.
                if let Some(work_journal_tx) = &work_journal_tx {
                    // We don't care if this message was successfully sent, we only use the journal
                    // during testing.
                    let _ = work_journal_tx.try_send(NOTHING_TO_DO);
                }
                None
            };

        work_event
    }

    // TODO(beacon-processor) this might be able to be moved to a more generalized location
    pub fn process_or_queue_work_event(
        &mut self,
        work: Work<E>,
        can_spawn: bool,
    ) -> Option<WorkType> {
        let work_id = work.str_id();

        let work_type = work.to_type();

        match work {
            _ if can_spawn => self.spawn_worker(work),
            Work::GossipAttestation { .. } => self.work_queues.attestation_queue.push(work),
            // Attestation batches are formed internally within the
            // `BeaconProcessor`, they are not sent from external services.
            Work::GossipAttestationBatch { .. } => crit!(
                    self.beacon_processor.log,
                    "Unsupported inbound event";
                    "type" => "GossipAttestationBatch"
            ),
            Work::GossipAggregate { .. } => self.work_queues.aggregate_queue.push(work),
            // Aggregate batches are formed internally within the `BeaconProcessor`,
            // they are not sent from external services.
            Work::GossipAggregateBatch { .. } => crit!(
                    self.beacon_processor.log,
                    "Unsupported inbound event";
                    "type" => "GossipAggregateBatch"
            ),
            Work::GossipBlock { .. } => {
                self.work_queues
                    .gossip_block_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::GossipBlobSidecar { .. } => {
                self.work_queues
                    .gossip_blob_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::GossipDataColumnSidecar { .. } => self.work_queues.gossip_data_column_queue.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::DelayedImportBlock { .. } => {
                self.work_queues
                    .delayed_block_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::GossipVoluntaryExit { .. } => self.work_queues.gossip_voluntary_exit_queue.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::GossipProposerSlashing { .. } => self
                .work_queues
                .gossip_proposer_slashing_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::GossipAttesterSlashing { .. } => self
                .work_queues
                .gossip_attester_slashing_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::GossipSyncSignature { .. } => self.work_queues.sync_message_queue.push(work),
            Work::GossipSyncContribution { .. } => {
                self.work_queues.sync_contribution_queue.push(work)
            }
            Work::GossipLightClientFinalityUpdate { .. } => self
                .work_queues
                .finality_update_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::GossipLightClientOptimisticUpdate { .. } => self
                .work_queues
                .optimistic_update_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::RpcBlock { .. } | Work::IgnoredRpcBlock { .. } => self
                .work_queues
                .rpc_block_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::RpcBlobs { .. } => {
                self.work_queues
                    .rpc_blob_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::RpcCustodyColumn { .. } => self.work_queues.rpc_custody_column_queue.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::RpcVerifyDataColumn(_) => self.work_queues.rpc_verify_data_column_queue.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::SamplingResult(_) => self.work_queues.sampling_result_queue.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::ChainSegment { .. } => {
                self.work_queues
                    .chain_segment_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::ChainSegmentBackfill { .. } => self.work_queues.backfill_chain_segment.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::Status { .. } => {
                self.work_queues
                    .status_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::BlocksByRangeRequest { .. } => {
                self.work_queues
                    .bbrange_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::BlocksByRootsRequest { .. } => {
                self.work_queues
                    .bbroots_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::BlobsByRangeRequest { .. } => {
                self.work_queues
                    .blbrange_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::LightClientBootstrapRequest { .. } => {
                self.work_queues
                    .lc_bootstrap_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::LightClientOptimisticUpdateRequest { .. } => self
                .work_queues
                .lc_optimistic_update_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::LightClientFinalityUpdateRequest { .. } => self
                .work_queues
                .lc_finality_update_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::UnknownBlockAttestation { .. } => {
                self.work_queues.unknown_block_attestation_queue.push(work)
            }
            Work::UnknownBlockAggregate { .. } => {
                self.work_queues.unknown_block_aggregate_queue.push(work)
            }
            Work::GossipBlsToExecutionChange { .. } => self
                .work_queues
                .gossip_bls_to_execution_change_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::BlobsByRootsRequest { .. } => {
                self.work_queues
                    .blbroots_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::DataColumnsByRootsRequest { .. } => {
                self.work_queues
                    .dcbroots_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::DataColumnsByRangeRequest { .. } => {
                self.work_queues
                    .dcbrange_queue
                    .push(work, work_id, &self.beacon_processor.log)
            }
            Work::UnknownLightClientOptimisticUpdate { .. } => self
                .work_queues
                .unknown_light_client_update_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::UnknownBlockSamplingRequest { .. } => self
                .work_queues
                .unknown_block_sampling_request_queue
                .push(work, work_id, &self.beacon_processor.log),
            Work::ApiRequestP0 { .. } => self.work_queues.api_request_p0_queue.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::ApiRequestP1 { .. } => self.work_queues.api_request_p1_queue.push(
                work,
                work_id,
                &self.beacon_processor.log,
            ),
            Work::Reprocess { .. } => {
                // TODO(beacon-processor) what to do here
                todo!()
            }
        }
        Some(work_type)
    }

    fn update_queue_metrics(&mut self, modified_queue_id: Option<WorkType>) {
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_WORKERS_ACTIVE_TOTAL,
            self.beacon_processor.current_workers as i64,
        );

        if let Some(modified_queue_id) = modified_queue_id {
            let queue_len = match modified_queue_id {
                WorkType::GossipAttestation => self.work_queues.aggregate_queue.len(),
                WorkType::UnknownBlockAttestation => {
                    self.work_queues.unknown_block_attestation_queue.len()
                }
                WorkType::GossipAttestationBatch => 0, // No queue
                WorkType::GossipAggregate => self.work_queues.aggregate_queue.len(),
                WorkType::UnknownBlockAggregate => {
                    self.work_queues.unknown_block_aggregate_queue.len()
                }
                WorkType::UnknownLightClientOptimisticUpdate => {
                    self.work_queues.unknown_light_client_update_queue.len()
                }
                WorkType::UnknownBlockSamplingRequest => {
                    self.work_queues.unknown_block_sampling_request_queue.len()
                }
                WorkType::GossipAggregateBatch => 0, // No queue
                WorkType::GossipBlock => self.work_queues.gossip_block_queue.len(),
                WorkType::GossipBlobSidecar => self.work_queues.gossip_blob_queue.len(),
                WorkType::GossipDataColumnSidecar => {
                    self.work_queues.gossip_data_column_queue.len()
                }
                WorkType::DelayedImportBlock => self.work_queues.delayed_block_queue.len(),
                WorkType::GossipVoluntaryExit => self.work_queues.gossip_voluntary_exit_queue.len(),
                WorkType::GossipProposerSlashing => {
                    self.work_queues.gossip_proposer_slashing_queue.len()
                }
                WorkType::GossipAttesterSlashing => {
                    self.work_queues.gossip_attester_slashing_queue.len()
                }
                WorkType::GossipSyncSignature => self.work_queues.sync_message_queue.len(),
                WorkType::GossipSyncContribution => self.work_queues.sync_contribution_queue.len(),
                WorkType::GossipLightClientFinalityUpdate => {
                    self.work_queues.finality_update_queue.len()
                }
                WorkType::GossipLightClientOptimisticUpdate => {
                    self.work_queues.optimistic_update_queue.len()
                }
                WorkType::RpcBlock => self.work_queues.rpc_block_queue.len(),
                WorkType::RpcBlobs | WorkType::IgnoredRpcBlock => {
                    self.work_queues.rpc_blob_queue.len()
                }
                WorkType::RpcCustodyColumn => self.work_queues.rpc_custody_column_queue.len(),
                WorkType::RpcVerifyDataColumn => {
                    self.work_queues.rpc_verify_data_column_queue.len()
                }
                WorkType::SamplingResult => self.work_queues.sampling_result_queue.len(),
                WorkType::ChainSegment => self.work_queues.chain_segment_queue.len(),
                WorkType::ChainSegmentBackfill => self.work_queues.backfill_chain_segment.len(),
                WorkType::Status => self.work_queues.status_queue.len(),
                WorkType::BlocksByRangeRequest => self.work_queues.blbrange_queue.len(),
                WorkType::BlocksByRootsRequest => self.work_queues.blbroots_queue.len(),
                WorkType::BlobsByRangeRequest => self.work_queues.bbrange_queue.len(),
                WorkType::BlobsByRootsRequest => self.work_queues.bbroots_queue.len(),
                WorkType::DataColumnsByRootsRequest => self.work_queues.dcbroots_queue.len(),
                WorkType::DataColumnsByRangeRequest => self.work_queues.dcbrange_queue.len(),
                WorkType::GossipBlsToExecutionChange => {
                    self.work_queues.gossip_bls_to_execution_change_queue.len()
                }
                WorkType::LightClientBootstrapRequest => self.work_queues.lc_bootstrap_queue.len(),
                WorkType::LightClientOptimisticUpdateRequest => {
                    self.work_queues.lc_optimistic_update_queue.len()
                }
                WorkType::LightClientFinalityUpdateRequest => {
                    self.work_queues.lc_finality_update_queue.len()
                }
                WorkType::ApiRequestP0 => self.work_queues.api_request_p0_queue.len(),
                WorkType::ApiRequestP1 => self.work_queues.api_request_p1_queue.len(),
                WorkType::Reprocess => 0,
            };
            metrics::observe_vec(
                &metrics::BEACON_PROCESSOR_QUEUE_LENGTH,
                &[modified_queue_id.into()],
                queue_len as f64,
            );
        }

        if self.work_queues.aggregate_queue.is_full()
            && self.work_queues.aggregate_debounce.elapsed()
        {
            error!(
                self.beacon_processor.log,
                "Aggregate attestation queue full";
                "msg" => "the system has insufficient resources for load",
                "queue_len" => self.work_queues.aggregate_queue.max_length,
            )
        }

        if self.work_queues.attestation_queue.is_full()
            && self.work_queues.attestation_debounce.elapsed()
        {
            error!(
                self.beacon_processor.log,
                "Attestation queue full";
                "msg" => "the system has insufficient resources for load",
                "queue_len" => self.work_queues.attestation_queue.max_length,
            )
        }
    }

    // TODO(beacon-processor) this can live outside of this struct in a more general location
    fn worker_journal(
        &self,
        work_event: &Option<WorkEvent<E>>,
        work_journal_tx: &Option<Sender<&'static str>>,
    ) {
        if let Some(work_journal_tx) = work_journal_tx {
            let id = work_event
                .as_ref()
                .map(|event| event.work.str_id())
                .unwrap_or(WORKER_FREED);

            // We don't care if this message was successfully sent, we only use the journal
            // during testing.
            let _ = work_journal_tx.try_send(id);
        }
    }

    // TODO(beacon-processor) this can live outside of this struct in a more general location
    fn increment_metrics(&self, work_event: &Option<WorkEvent<E>>) -> Option<HistogramTimer> {
        let _event_timer = metrics::start_timer(&metrics::BEACON_PROCESSOR_EVENT_HANDLING_SECONDS);
        if let Some(event) = work_event {
            metrics::inc_counter_vec(
                &metrics::BEACON_PROCESSOR_WORK_EVENTS_RX_COUNT,
                &[event.work.str_id()],
            );
        } else {
            metrics::inc_counter(&metrics::BEACON_PROCESSOR_IDLE_EVENTS_TOTAL);
        }
        _event_timer
    }

    // TODO(beacon-processor) should we move spawn_worker outside of self?
    /// Spawns a blocking worker thread to process some `Work`.
    ///
    /// Sends an message on `idle_tx` when the work is complete and the task is stopping.
    fn spawn_worker(&mut self, work: Work<E>) {
        let work_id = work.str_id();
        let worker_timer =
            metrics::start_timer_vec(&metrics::BEACON_PROCESSOR_WORKER_TIME, &[work_id]);
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
            tx: self.outbound_events.idle_tx.clone(),
            _worker_timer: worker_timer,
            log: self.beacon_processor.log.clone(),
        };

        let worker_id = self.beacon_processor.current_workers;
        self.beacon_processor.current_workers = self.beacon_processor.current_workers.saturating_add(1);

        let executor = self.beacon_processor.executor.clone();

        trace!(
            self.beacon_processor.log,
            "Spawning beacon processor worker";
            "work" => work_id,
            "worker" => worker_id,
        );

        let task_spawner = TaskSpawner {
            executor,
            send_idle_on_drop,
        };

        match work {
            Work::GossipAttestation {
                attestation,
                process_individual,
                process_batch: _,
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
            | Work::RpcBlobs { process_fn }
            | Work::RpcCustodyColumn(process_fn)
            | Work::RpcVerifyDataColumn(process_fn)
            | Work::SamplingResult(process_fn) => task_spawner.spawn_async(process_fn),
            Work::IgnoredRpcBlock { process_fn } => task_spawner.spawn_blocking(process_fn),
            Work::GossipBlock(work)
            | Work::GossipBlobSidecar(work)
            | Work::GossipDataColumnSidecar(work) => task_spawner.spawn_async(async move {
                work.await;
            }),
            Work::BlobsByRangeRequest(process_fn)
            | Work::BlobsByRootsRequest(process_fn)
            | Work::DataColumnsByRootsRequest(process_fn)
            | Work::DataColumnsByRangeRequest(process_fn) => {
                task_spawner.spawn_blocking(process_fn)
            }
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
            | Work::LightClientFinalityUpdateRequest(process_fn) => {
                task_spawner.spawn_blocking(process_fn)
            }
            Work::Reprocess(reprocess_message) => {
                // TODO(beacon-processor) send to the reprocess queue
                todo!()
            }
        };
    }
}
