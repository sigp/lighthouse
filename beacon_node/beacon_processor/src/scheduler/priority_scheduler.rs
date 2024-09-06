// The priority scheduler has three major facets
// 1. A priority ordering system
// 2. A backfill rate limiting feature
// 3. A retry queue

use slog::error;
use slot_clock::SlotClock;
use std::{cmp, sync::Arc, time::Duration};

use futures::StreamExt;
use lighthouse_metrics::HistogramTimer;
use logging::TimeLatch;
use slog::{crit, debug, trace, warn};
use tokio::sync::mpsc::{self, Receiver, Sender};
use types::EthSpec;

use crate::{
    metrics, work_reprocessing_queue::{spawn_reprocess_scheduler, ReadyWork}, BeaconProcessor, BeaconProcessorQueueLengths, FifoQueue, InboundEvent, InboundEvents, LifoQueue, Work, WorkEvent, NOTHING_TO_DO, WORKER_FREED
};

// TODO(beacon-processor) this will be impl specific
pub struct WorkQueues<E: EthSpec> {
    pub aggregate_queue: LifoQueue<Work<E>>,
    pub aggregate_debounce: TimeLatch,
    pub attestation_queue: LifoQueue<Work<E>>,
    pub attestation_debounce: TimeLatch,
    pub unknown_block_aggregate_queue: LifoQueue<Work<E>>,
    pub unknown_block_attestation_queue: LifoQueue<Work<E>>,
    pub sync_message_queue: LifoQueue<Work<E>>,
    pub sync_contribution_queue: LifoQueue<Work<E>>,
    pub gossip_voluntary_exit_queue: FifoQueue<Work<E>>,
    pub gossip_proposer_slashing_queue: FifoQueue<Work<E>>,
    pub gossip_attester_slashing_queue: FifoQueue<Work<E>>,
    pub finality_update_queue: FifoQueue<Work<E>>,
    pub optimistic_update_queue: FifoQueue<Work<E>>,
    pub unknown_light_client_update_queue: FifoQueue<Work<E>>,
    pub unknown_block_sampling_request_queue: FifoQueue<Work<E>>,
    pub rpc_block_queue: FifoQueue<Work<E>>,
    pub rpc_blob_queue: FifoQueue<Work<E>>,
    pub rpc_custody_column_queue: FifoQueue<Work<E>>,
    pub rpc_verify_data_column_queue: FifoQueue<Work<E>>,
    pub sampling_result_queue: FifoQueue<Work<E>>,
    pub chain_segment_queue: FifoQueue<Work<E>>,
    pub backfill_chain_segment: FifoQueue<Work<E>>,
    pub gossip_block_queue: FifoQueue<Work<E>>,
    pub gossip_blob_queue: FifoQueue<Work<E>>,
    pub gossip_data_column_queue: FifoQueue<Work<E>>,
    pub delayed_block_queue: FifoQueue<Work<E>>,
    pub status_queue: FifoQueue<Work<E>>,
    pub bbrange_queue: FifoQueue<Work<E>>,
    pub bbroots_queue: FifoQueue<Work<E>>,
    pub blbroots_queue: FifoQueue<Work<E>>,
    pub blbrange_queue: FifoQueue<Work<E>>,
    pub dcbroots_queue: FifoQueue<Work<E>>,
    pub dcbrange_queue: FifoQueue<Work<E>>,
    pub gossip_bls_to_execution_change_queue: FifoQueue<Work<E>>,
    pub lc_bootstrap_queue: FifoQueue<Work<E>>,
    pub lc_optimistic_update_queue: FifoQueue<Work<E>>,
    pub lc_finality_update_queue: FifoQueue<Work<E>>,
    pub api_request_p0_queue: FifoQueue<Work<E>>,
    pub api_request_p1_queue: FifoQueue<Work<E>>,
}

impl<E: EthSpec> WorkQueues<E> {
    pub fn new(queue_lengths: BeaconProcessorQueueLengths) -> Self {
        let aggregate_queue = LifoQueue::new(queue_lengths.aggregate_queue);
        let aggregate_debounce = TimeLatch::default();
        let attestation_queue = LifoQueue::new(queue_lengths.attestation_queue);
        let attestation_debounce = TimeLatch::default();
        let unknown_block_aggregate_queue =
            LifoQueue::new(queue_lengths.unknown_block_aggregate_queue);
        let unknown_block_attestation_queue =
            LifoQueue::new(queue_lengths.unknown_block_attestation_queue);

        let sync_message_queue = LifoQueue::new(queue_lengths.sync_message_queue);
        let sync_contribution_queue = LifoQueue::new(queue_lengths.sync_contribution_queue);

        // Using a FIFO queue for voluntary exits since it prevents exit censoring. I don't have
        // a strong feeling about queue type for exits.
        let gossip_voluntary_exit_queue =
            FifoQueue::new(queue_lengths.gossip_voluntary_exit_queue);

        // Using a FIFO queue for slashing to prevent people from flushing their slashings from the
        // queues with lots of junk messages.
        let gossip_proposer_slashing_queue =
            FifoQueue::new(queue_lengths.gossip_proposer_slashing_queue);
        let gossip_attester_slashing_queue =
            FifoQueue::new(queue_lengths.gossip_attester_slashing_queue);

        // Using a FIFO queue for light client updates to maintain sequence order.
        let finality_update_queue = FifoQueue::new(queue_lengths.finality_update_queue);
        let optimistic_update_queue = FifoQueue::new(queue_lengths.optimistic_update_queue);
        let unknown_light_client_update_queue =
            FifoQueue::new(queue_lengths.unknown_light_client_update_queue);
        let unknown_block_sampling_request_queue =
            FifoQueue::new(queue_lengths.unknown_block_sampling_request_queue);

        // Using a FIFO queue since blocks need to be imported sequentially.
        let rpc_block_queue = FifoQueue::new(queue_lengths.rpc_block_queue);
        let rpc_blob_queue = FifoQueue::new(queue_lengths.rpc_blob_queue);
        let rpc_custody_column_queue = FifoQueue::new(queue_lengths.rpc_custody_column_queue);
        let rpc_verify_data_column_queue =
            FifoQueue::new(queue_lengths.rpc_verify_data_column_queue);
        let sampling_result_queue = FifoQueue::new(queue_lengths.sampling_result_queue);
        let chain_segment_queue = FifoQueue::new(queue_lengths.chain_segment_queue);
        let backfill_chain_segment = FifoQueue::new(queue_lengths.backfill_chain_segment);
        let gossip_block_queue = FifoQueue::new(queue_lengths.gossip_block_queue);
        let gossip_blob_queue = FifoQueue::new(queue_lengths.gossip_blob_queue);
        let gossip_data_column_queue = FifoQueue::new(queue_lengths.gossip_data_column_queue);
        let delayed_block_queue = FifoQueue::new(queue_lengths.delayed_block_queue);

        let status_queue = FifoQueue::new(queue_lengths.status_queue);
        let bbrange_queue = FifoQueue::new(queue_lengths.bbrange_queue);
        let bbroots_queue = FifoQueue::new(queue_lengths.bbroots_queue);
        let blbroots_queue = FifoQueue::new(queue_lengths.blbroots_queue);
        let blbrange_queue = FifoQueue::new(queue_lengths.blbrange_queue);
        let dcbroots_queue = FifoQueue::new(queue_lengths.dcbroots_queue);
        let dcbrange_queue = FifoQueue::new(queue_lengths.dcbrange_queue);

        let gossip_bls_to_execution_change_queue =
            FifoQueue::new(queue_lengths.gossip_bls_to_execution_change_queue);

        let lc_bootstrap_queue = FifoQueue::new(queue_lengths.lc_bootstrap_queue);
        let lc_optimistic_update_queue =
            FifoQueue::new(queue_lengths.lc_optimistic_update_queue);
        let lc_finality_update_queue = FifoQueue::new(queue_lengths.lc_finality_update_queue);

        let api_request_p0_queue = FifoQueue::new(queue_lengths.api_request_p0_queue);
        let api_request_p1_queue = FifoQueue::new(queue_lengths.api_request_p1_queue);

        WorkQueues {
            aggregate_queue,
            aggregate_debounce,
            attestation_queue,
            attestation_debounce,
            unknown_block_aggregate_queue,
            unknown_block_attestation_queue,
            sync_message_queue,
            sync_contribution_queue,
            gossip_voluntary_exit_queue,
            gossip_proposer_slashing_queue,
            gossip_attester_slashing_queue,
            finality_update_queue,
            optimistic_update_queue,
            unknown_light_client_update_queue,
            unknown_block_sampling_request_queue,
            rpc_block_queue,
            rpc_blob_queue,
            rpc_custody_column_queue,
            rpc_verify_data_column_queue,
            sampling_result_queue,
            chain_segment_queue,
            backfill_chain_segment,
            gossip_block_queue,
            gossip_blob_queue,
            gossip_data_column_queue,
            delayed_block_queue,
            status_queue,
            bbrange_queue,
            bbroots_queue,
            blbroots_queue,
            blbrange_queue,
            dcbroots_queue,
            dcbrange_queue,
            gossip_bls_to_execution_change_queue,
            lc_bootstrap_queue,
            lc_optimistic_update_queue,
            lc_finality_update_queue,
            api_request_p0_queue,
            api_request_p1_queue,
        }
    }
}

// Backend trait inits a channel, a run function
// A channel trait has send_work, reprocess_work etc.

pub struct Scheduler<E: EthSpec> {
    beacon_processor: BeaconProcessor<E>,
    enable_backfill_rate_limiting: bool,
    current_workers: usize,
    idle_tx: Sender<()>,
    idle_rx: Receiver<()>,
    work_queues: WorkQueues<E>,
}

impl<E: EthSpec> Scheduler<E> {
    pub async fn process_work_event(&self) {}

    async fn run<S: SlotClock + 'static>(
        mut self,
        mut inbound_events: InboundEvents<E>,
        work_journal_tx: Option<Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
    ) -> Result<(), String> {
        // Channels for sending work to the re-process scheduler (`work_reprocessing_tx`) and to
        // receive them back once they are ready (`ready_work_rx`).
        let (ready_work_tx, ready_work_rx) =
            mpsc::channel::<ReadyWork>(self.beacon_processor.config.max_scheduled_work_queue_len);
        // TODO(beacon-processor) reprocess scheduler
        spawn_reprocess_scheduler(
            ready_work_tx,
            work_reprocessing_rx,
            &self.beacon_processor.executor,
            Arc::new(slot_clock),
            self.beacon_processor.log.clone(),
            maximum_gossip_clock_disparity,
        )?;

        let work_event = match inbound_events.next().await {
            Some(InboundEvent::WorkerIdle) => {
                // TODO(beacon-processor) move current_workers from beacon_processor to self
                self.current_workers = self.current_workers.saturating_sub(1);
                None
            }
            Some(InboundEvent::WorkEvent(event)) if self.enable_backfill_rate_limiting => {
                // TODO(beacon-processor) is backfill rate limiting going to be the same across all schedulers?
                todo!()
            }
            Some(InboundEvent::WorkEvent(event)) | Some(InboundEvent::ReprocessingWork(event)) => {
                Some(event)
            }
            None => {
                debug!(
                    self.beacon_processor.log,
                    "Gossip processor stopped";
                    "msg" => "stream ended"
                );
                // TODO(beacon-processor) this should terminate the whole process
                todo!()
            }
        };

        let _event_timer = self.increment_metrics(&work_event);
        self.worker_journal(&work_event, &work_journal_tx);

        let can_spawn = self.current_workers < self.beacon_processor.config.max_workers;
        let drop_during_sync = work_event
            .as_ref()
            .map_or(false, |event| event.drop_during_sync);

        match work_event {
            // There is no new work event, but we are able to spawn a new worker.
            //
            // We don't check the `work.drop_during_sync` here. We assume that if it made
            // it into the queue at any point then we should process it.
            None if can_spawn => {
                // TODO(beacon-processor) implement the normal priority scheduler here
                // also note that these match arms will look similar across all scheduler variants
                // so maybe we can pull this function out and get creative with closure usage
                self.priority_scheduler(&work_journal_tx);
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
            }

            // There is a new work event and the chain is not syncing. Process it or queue
            // it.
            Some(WorkEvent { work, .. }) => {
                self.process_or_queue_work_event(work, can_spawn);
            }
        }
    }

    fn priority_scheduler(&mut self, work_journal_tx: &Option<Sender<&'static str>>) {
        let idle_tx = self.idle_tx.clone();
        // Check for chain segments first, they're the most efficient way to get
        // blocks into the system.
        if let Some(item) = self.work_queues.chain_segment_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check sync blocks before gossip blocks, since we've already explicitly
        // requested these blocks.
        } else if let Some(item) = self.work_queues.rpc_block_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.rpc_blob_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.rpc_custody_column_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // TODO(das): decide proper prioritization for sampling columns
        } else if let Some(item) = self.work_queues.rpc_custody_column_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.rpc_verify_data_column_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.sampling_result_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check delayed blocks before gossip blocks, the gossip blocks might rely
        // on the delayed ones.
        } else if let Some(item) = self.work_queues.delayed_block_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check gossip blocks before gossip attestations, since a block might be
        // required to verify some attestations.
        } else if let Some(item) = self.work_queues.gossip_block_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.gossip_blob_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.gossip_data_column_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check the priority 0 API requests after blocks and blobs, but before attestations.
        } else if let Some(item) = self.work_queues.api_request_p0_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
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
                if let Some(item) = self.work_queues.aggregate_queue.pop() {
                    self.beacon_processor.spawn_worker(item, idle_tx);
                }
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
                    self.beacon_processor.spawn_worker(
                        Work::GossipAggregateBatch {
                            aggregates,
                            process_batch,
                        },
                        idle_tx,
                    )
                } else {
                    // There is no good reason for this to
                    // happen, it is a serious logic error.
                    // Since we only form batches when multiple
                    // work items exist, we should always have a
                    // work closure at this point.
                    crit!(self.beacon_processor.log, "Missing aggregate work");
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
                if let Some(item) = self.work_queues.attestation_queue.pop() {
                    self.beacon_processor.spawn_worker(item, idle_tx);
                }
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
                    self.beacon_processor.spawn_worker(
                        Work::GossipAttestationBatch {
                            attestations,
                            process_batch,
                        },
                        idle_tx,
                    )
                } else {
                    // There is no good reason for this to
                    // happen, it is a serious logic error.
                    // Since we only form batches when multiple
                    // work items exist, we should always have a
                    // work closure at this point.
                    crit!(self.beacon_processor.log, "Missing attestations work");
                }
            }
        // Check sync committee messages after attestations as their rewards are lesser
        // and they don't influence fork choice.
        } else if let Some(item) = self.work_queues.sync_contribution_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.sync_message_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Aggregates and unaggregates queued for re-processing are older and we
        // care about fresher ones, so check those first.
        } else if let Some(item) = self.work_queues.unknown_block_aggregate_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.unknown_block_attestation_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check RPC methods next. Status messages are needed for sync so
        // prioritize them over syncing requests from other peers (BlocksByRange
        // and BlocksByRoot)
        } else if let Some(item) = self.work_queues.status_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.bbrange_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.bbroots_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.blbrange_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.blbroots_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.dcbroots_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.dcbrange_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Prioritize sampling requests after block syncing requests
        } else if let Some(item) = self.work_queues.unknown_block_sampling_request_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check slashings after all other consensus messages so we prioritize
        // following head.
        //
        // Check attester slashings before proposer slashings since they have the
        // potential to slash multiple validators at once.
        } else if let Some(item) = self.work_queues.gossip_attester_slashing_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.gossip_proposer_slashing_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check exits and address changes late since our validators don't get
        // rewards from them.
        } else if let Some(item) = self.work_queues.gossip_voluntary_exit_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.gossip_bls_to_execution_change_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Check the priority 1 API requests after we've
        // processed all the interesting things from the network
        // and things required for us to stay in good repute
        // with our P2P peers.
        } else if let Some(item) = self.work_queues.api_request_p1_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Handle backfill sync chain segments.
        } else if let Some(item) = self.work_queues.backfill_chain_segment.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        // Handle light client requests.
        } else if let Some(item) = self.work_queues.lc_bootstrap_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.lc_optimistic_update_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
        } else if let Some(item) = self.work_queues.lc_finality_update_queue.pop() {
            self.beacon_processor.spawn_worker(item, idle_tx);
            // This statement should always be the final else statement.
        } else {
            // Let the journal know that a worker is freed and there's nothing else
            // for it to do.
            if let Some(work_journal_tx) = work_journal_tx {
                // We don't care if this message was successfully sent, we only use the journal
                // during testing.
                let _ = work_journal_tx.try_send(NOTHING_TO_DO);
            }
        }
    }

    // TODO(beacon-processor) this might be able to be moved to a more generalized location
    pub fn process_or_queue_work_event(&mut self, work: Work<E>, can_spawn: bool) {
        let work_id = work.str_id();

        match work {
            _ if can_spawn => self
                .beacon_processor
                .spawn_worker(work, self.idle_tx.clone()),
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
        }

        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_WORKERS_ACTIVE_TOTAL,
            self.current_workers as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_QUEUE_TOTAL,
            self.work_queues.attestation_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_QUEUE_TOTAL,
            self.work_queues.aggregate_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_SYNC_MESSAGE_QUEUE_TOTAL,
            self.work_queues.sync_message_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_SYNC_CONTRIBUTION_QUEUE_TOTAL,
            self.work_queues.sync_contribution_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_QUEUE_TOTAL,
            self.work_queues.gossip_block_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_GOSSIP_BLOB_QUEUE_TOTAL,
            self.work_queues.gossip_blob_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_GOSSIP_DATA_COLUMN_QUEUE_TOTAL,
            self.work_queues.gossip_data_column_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_RPC_BLOCK_QUEUE_TOTAL,
            self.work_queues.rpc_block_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_RPC_BLOB_QUEUE_TOTAL,
            self.work_queues.rpc_blob_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_RPC_CUSTODY_COLUMN_QUEUE_TOTAL,
            self.work_queues.rpc_custody_column_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_RPC_VERIFY_DATA_COLUMN_QUEUE_TOTAL,
            self.work_queues.rpc_verify_data_column_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_SAMPLING_RESULT_QUEUE_TOTAL,
            self.work_queues.sampling_result_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_QUEUE_TOTAL,
            self.work_queues.chain_segment_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_QUEUE_TOTAL,
            self.work_queues.backfill_chain_segment.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_EXIT_QUEUE_TOTAL,
            self.work_queues.gossip_voluntary_exit_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_PROPOSER_SLASHING_QUEUE_TOTAL,
            self.work_queues.gossip_proposer_slashing_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_ATTESTER_SLASHING_QUEUE_TOTAL,
            self.work_queues.gossip_attester_slashing_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_QUEUE_TOTAL,
            self.work_queues.gossip_bls_to_execution_change_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_API_REQUEST_P0_QUEUE_TOTAL,
            self.work_queues.api_request_p0_queue.len() as i64,
        );
        metrics::set_gauge(
            &metrics::BEACON_PROCESSOR_API_REQUEST_P1_QUEUE_TOTAL,
            self.work_queues.api_request_p1_queue.len() as i64,
        );

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
}
