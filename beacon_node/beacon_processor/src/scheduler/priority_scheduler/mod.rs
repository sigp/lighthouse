// The priority scheduler has three major facets
// 1. A priority ordering system
// 2. A backfill rate limiting feature
// 3. A retry queue

mod work_queue;

use crate::scheduler::work_reprocessing_queue::{spawn_reprocess_scheduler, ReadyWork};
use crate::scheduler::InboundEvents;
use logging::crit;
use slot_clock::SlotClock;
use std::{cmp, marker::PhantomData, sync::Arc, time::Duration};
use tokio::sync::mpsc::{self, Sender};
use tracing::{error, trace, warn};
use types::{BeaconState, ChainSpec, EthSpec};
use work_queue::{BeaconProcessorQueueLengths, WorkQueues};

use crate::{
    metrics, BeaconProcessor, ReprocessQueueMessage, Work, WorkEvent, WorkType, MAX_IDLE_QUEUE_LEN,
    NOTHING_TO_DO,
};

use super::{spawn_worker, worker_journal, NextWorkEvent};

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "priority_scheduler";

// Backend trait inits a channel, a run function
// A channel trait has send_work, reprocess_work etc.
pub struct Scheduler<E: EthSpec, S: SlotClock> {
    beacon_processor: BeaconProcessor<E>,
    work_queues: WorkQueues<E>,
    phantom_data: PhantomData<S>,
}

impl<E: EthSpec, S: SlotClock + 'static> Scheduler<E, S> {
    pub fn new(
        beacon_processor: BeaconProcessor<E>,
        beacon_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Self, String> {
        // Used by workers to communicate that they are finished a task.

        let queue_lengths = BeaconProcessorQueueLengths::from_state(beacon_state, spec)?;

        // Initialize the worker queues.
        let work_queues: WorkQueues<E> = WorkQueues::new(queue_lengths);

        Ok(Self {
            beacon_processor,
            work_queues,
            phantom_data: PhantomData,
        })
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

        let mut inbound_events = InboundEvents {
            idle_rx,
            event_rx,
            ready_work_rx,
        };

        spawn_reprocess_scheduler(
            ready_work_tx,
            reprocess_work_rx,
            &self.beacon_processor.executor,
            Arc::new(slot_clock),
            maximum_gossip_clock_disparity,
        )?;

        let executor = self.beacon_processor.executor.clone();
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

                let _event_timer = self.increment_metrics(&work_event);
                worker_journal(&work_event, &work_journal_tx);

                let can_spawn = self.beacon_processor.current_workers
                    < self.beacon_processor.config.max_workers;
                let drop_during_sync = work_event
                    .as_ref()
                    .is_some_and(|event| event.drop_during_sync);

                let modified_queue_id = match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        let work_event = self.priority_scheduler(&work_journal_tx);
                        if let Some(work_event) = work_event {
                            let work_type = work_event.to_type();
                            spawn_worker(&mut self.beacon_processor, idle_tx.clone(), work_event);
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
                            msg = "no new work and cannot spawn worker",
                            "Unexpected gossip processor condition",
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
                            work_id,
                            msg = "chain is syncing",
                            "Gossip processor skipping work",
                        );
                        None
                    }

                    // There is a new work event and the chain is not syncing. Process it or queue
                    // it.
                    Some(WorkEvent { work, .. }) => self.process_or_queue_work_event(
                        &reprocess_work_tx,
                        idle_tx.clone(),
                        work,
                        can_spawn,
                    ),
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
                                    error!("Invalid item in aggregate queue");
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
                        crit!("Missing aggregate work");
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
                                _ => error!("Invalid item in attestation queue"),
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
                        crit!("Missing attestations work");
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

    pub fn process_or_queue_work_event(
        &mut self,
        reprocess_work_tx: &Sender<ReprocessQueueMessage>,
        idle_tx: Sender<()>,
        work: Work<E>,
        can_spawn: bool,
    ) -> Option<WorkType> {
        let work_id = work.str_id();

        let work_type = work.to_type();

        match work {
            Work::Reprocess(work_event) => {
                if let Err(e) = reprocess_work_tx.try_send(work_event) {
                    error!(
                        error = ?e,
                        "Failed to reprocess work event"
                    )
                }
            }
            _ if can_spawn => spawn_worker(&mut self.beacon_processor, idle_tx.clone(), work),
            Work::GossipAttestation { .. } => self.work_queues.attestation_queue.push(work),
            Work::GossipAttestationToConvert { .. } => {
                self.work_queues.attestation_to_convert_queue.push(work)
            }
            // Attestation batches are formed internally within the
            // `BeaconProcessor`, they are not sent from external services.
            work_type @ Work::GossipAttestationBatch { .. } => {
                crit!(?work_type, "Unsupported inbound event")
            }
            Work::GossipAggregate { .. } => self.work_queues.aggregate_queue.push(work),
            // Aggregate batches are formed internally within the `BeaconProcessor`,
            // they are not sent from external services.
            work_type @ Work::GossipAggregateBatch { .. } => {
                crit!(?work_type, "Unsupported inbound event")
            }
            Work::GossipBlock { .. } | Work::GossipCanonicalBlock { .. } => {
                self.work_queues.gossip_block_queue.push(work, work_id)
            }
            Work::GossipBlobSidecar { .. } => {
                self.work_queues.gossip_blob_queue.push(work, work_id)
            }
            Work::GossipDataColumnSidecar { .. } => self
                .work_queues
                .gossip_data_column_queue
                .push(work, work_id),
            Work::DelayedImportBlock { .. } => {
                self.work_queues.delayed_block_queue.push(work, work_id)
            }
            Work::GossipVoluntaryExit { .. } => self
                .work_queues
                .gossip_voluntary_exit_queue
                .push(work, work_id),
            Work::GossipProposerSlashing { .. } => self
                .work_queues
                .gossip_proposer_slashing_queue
                .push(work, work_id),
            Work::GossipAttesterSlashing { .. } => self
                .work_queues
                .gossip_attester_slashing_queue
                .push(work, work_id),
            Work::GossipSyncSignature { .. } => self.work_queues.sync_message_queue.push(work),
            Work::GossipSyncContribution { .. } => {
                self.work_queues.sync_contribution_queue.push(work)
            }
            Work::GossipLightClientFinalityUpdate { .. } => {
                self.work_queues.finality_update_queue.push(work, work_id)
            }
            Work::GossipLightClientOptimisticUpdate { .. } => {
                self.work_queues.optimistic_update_queue.push(work, work_id)
            }
            Work::RpcBlock { .. }
            | Work::IgnoredRpcBlock { .. }
            | Work::RpcCanonicalBlock { .. } => {
                self.work_queues.rpc_block_queue.push(work, work_id)
            }
            Work::RpcBlobs { .. } => self.work_queues.rpc_blob_queue.push(work, work_id),
            Work::RpcCustodyColumn { .. } => self
                .work_queues
                .rpc_custody_column_queue
                .push(work, work_id),
            Work::RpcVerifyDataColumn(_) => self
                .work_queues
                .rpc_verify_data_column_queue
                .push(work, work_id),
            Work::SamplingResult(_) => self.work_queues.sampling_result_queue.push(work, work_id),
            Work::ChainSegment { .. } => self.work_queues.chain_segment_queue.push(work, work_id),
            Work::ChainSegmentBackfill { .. } => {
                self.work_queues.backfill_chain_segment.push(work, work_id)
            }
            Work::Status { .. } => self.work_queues.status_queue.push(work, work_id),
            Work::BlocksByRangeRequest { .. } => self.work_queues.bbrange_queue.push(work, work_id),
            Work::BlocksByRootsRequest { .. } => self.work_queues.bbroots_queue.push(work, work_id),
            Work::BlobsByRangeRequest { .. } => self.work_queues.blbrange_queue.push(work, work_id),
            Work::LightClientBootstrapRequest { .. } => {
                self.work_queues.lc_bootstrap_queue.push(work, work_id)
            }
            Work::LightClientOptimisticUpdateRequest { .. } => self
                .work_queues
                .lc_optimistic_update_queue
                .push(work, work_id),
            Work::LightClientFinalityUpdateRequest { .. } => self
                .work_queues
                .lc_finality_update_queue
                .push(work, work_id),
            Work::LightClientUpdatesByRangeRequest { .. } => {
                self.work_queues.lc_update_range_queue.push(work, work_id)
            }
            Work::UnknownBlockAttestation { .. } => {
                self.work_queues.unknown_block_attestation_queue.push(work)
            }
            Work::UnknownBlockAggregate { .. } => {
                self.work_queues.unknown_block_aggregate_queue.push(work)
            }
            Work::GossipBlsToExecutionChange { .. } => self
                .work_queues
                .gossip_bls_to_execution_change_queue
                .push(work, work_id),
            Work::BlobsByRootsRequest { .. } => self.work_queues.blbroots_queue.push(work, work_id),
            Work::DataColumnsByRootsRequest { .. } => {
                self.work_queues.dcbroots_queue.push(work, work_id)
            }
            Work::DataColumnsByRangeRequest { .. } => {
                self.work_queues.dcbrange_queue.push(work, work_id)
            }
            Work::UnknownLightClientOptimisticUpdate { .. } => self
                .work_queues
                .unknown_light_client_update_queue
                .push(work, work_id),
            Work::UnknownBlockSamplingRequest { .. } => self
                .work_queues
                .unknown_block_sampling_request_queue
                .push(work, work_id),
            Work::ApiRequestP0 { .. } => self.work_queues.api_request_p0_queue.push(work, work_id),
            Work::ApiRequestP1 { .. } => self.work_queues.api_request_p1_queue.push(work, work_id),
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
                WorkType::GossipAttestationToConvert => self.work_queues.aggregate_queue.len(),
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
                WorkType::GossipBlock | WorkType::GossipCanonicalBlock => {
                    self.work_queues.gossip_block_queue.len()
                }
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
                WorkType::RpcBlock | WorkType::RpcCanonicalBlock => {
                    self.work_queues.rpc_block_queue.len()
                }
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
                WorkType::LightClientUpdatesByRangeRequest => {
                    self.work_queues.lc_update_range_queue.len()
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
                msg = "the system has insufficient resources for load",
                queue_len = self.work_queues.aggregate_queue.max_length,
                "Aggregate attestation queue full",
            )
        }

        if self.work_queues.attestation_queue.is_full()
            && self.work_queues.attestation_debounce.elapsed()
        {
            error!(
                msg = "the system has insufficient resources for load",
                queue_len = self.work_queues.attestation_queue.max_length,
                "Attestation queue full",
            )
        }
    }

    // TODO(beacon-processor) this can live outside of this struct in a more general location
    fn increment_metrics(
        &self,
        work_event: &Option<WorkEvent<E>>,
    ) -> Option<metrics::HistogramTimer> {
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
