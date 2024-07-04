//! Provides a mechanism which queues work for later processing.
//!
//! When the `beacon_processor::Worker` imports a block that is acceptably early (i.e., within the
//! gossip propagation tolerance) it will send it to this queue where it will be placed in a
//! `DelayQueue` until the slot arrives. Once the block has been determined to be ready, it will be
//! sent back out on a channel to be processed by the `BeaconProcessor` again.
//!
//! There is the edge-case where the slot arrives before this queue manages to process it. In that
//! case, the block will be sent off for immediate processing (skipping the `DelayQueue`).
//!
//! Aggregated and unaggregated attestations that failed verification due to referencing an unknown
//! block will be re-queued until their block is imported, or until they expire.
use crate::metrics;
use crate::{AsyncFn, BlockingFn, Work, WorkEvent};
use fnv::FnvHashMap;
use futures::task::Poll;
use futures::{Stream, StreamExt};
use itertools::Itertools;
use logging::TimeLatch;
use slog::{crit, debug, error, trace, warn, Logger};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::time::Duration;
use strum::AsRefStr;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::time::delay_queue::{DelayQueue, Key as DelayKey};
use types::{EthSpec, Hash256, Slot};

const TASK_NAME: &str = "beacon_processor_reprocess_queue";
const GOSSIP_BLOCKS: &str = "gossip_blocks";
const RPC_BLOCKS: &str = "rpc_blocks";
const ATTESTATIONS: &str = "attestations";
const LIGHT_CLIENT_UPDATES: &str = "lc_updates";

/// Queue blocks for re-processing with an `ADDITIONAL_QUEUED_BLOCK_DELAY` after the slot starts.
/// This is to account for any slight drift in the system clock.
pub const ADDITIONAL_QUEUED_BLOCK_DELAY: Duration = Duration::from_millis(5);

/// For how long to queue aggregated and unaggregated attestations for re-processing.
pub const QUEUED_ATTESTATION_DELAY: Duration = Duration::from_secs(12);

/// For how long to queue light client updates for re-processing.
pub const QUEUED_LIGHT_CLIENT_UPDATE_DELAY: Duration = Duration::from_secs(12);

/// For how long to queue rpc blocks before sending them back for reprocessing.
pub const QUEUED_RPC_BLOCK_DELAY: Duration = Duration::from_secs(4);

/// Set an arbitrary upper-bound on the number of queued blocks to avoid DoS attacks. The fact that
/// we signature-verify blocks before putting them in the queue *should* protect against this, but
/// it's nice to have extra protection.
const MAXIMUM_QUEUED_BLOCKS: usize = 16;

/// How many attestations we keep before new ones get dropped.
const MAXIMUM_QUEUED_ATTESTATIONS: usize = 16_384;

/// How many light client updates we keep before new ones get dropped.
const MAXIMUM_QUEUED_LIGHT_CLIENT_UPDATES: usize = 128;

// Process backfill batch 50%, 60%, 80% through each slot.
//
// Note: use caution to set these fractions in a way that won't cause panic-y
// arithmetic.
pub const BACKFILL_SCHEDULE_IN_SLOT: [(u32, u32); 3] = [
    // One half: 6s on mainnet, 2.5s on Gnosis.
    (1, 2),
    // Three fifths: 7.2s on mainnet, 3s on Gnosis.
    (3, 5),
    // Four fifths: 9.6s on mainnet, 4s on Gnosis.
    (4, 5),
];

/// Messages that the scheduler can receive.
#[derive(AsRefStr)]
pub enum ReprocessQueueMessage {
    /// A block that has been received early and we should queue for later processing.
    EarlyBlock(QueuedGossipBlock),
    /// A gossip block for hash `X` is being imported, we should queue the rpc block for the same
    /// hash until the gossip block is imported.
    RpcBlock(QueuedRpcBlock),
    /// A block that was successfully processed. We use this to handle attestations updates
    /// for unknown blocks.
    BlockImported {
        block_root: Hash256,
        parent_root: Hash256,
    },
    /// A new `LightClientOptimisticUpdate` has been produced. We use this to handle light client
    /// updates for unknown parent blocks.
    NewLightClientOptimisticUpdate { parent_root: Hash256 },
    /// An unaggregated attestation that references an unknown block.
    UnknownBlockUnaggregate(QueuedUnaggregate),
    /// An aggregated attestation that references an unknown block.
    UnknownBlockAggregate(QueuedAggregate),
    /// A light client optimistic update that references a parent root that has not been seen as a parent.
    UnknownLightClientOptimisticUpdate(QueuedLightClientUpdate),
    /// A new backfill batch that needs to be scheduled for processing.
    BackfillSync(QueuedBackfillBatch),
}

/// Events sent by the scheduler once they are ready for re-processing.
pub enum ReadyWork {
    Block(QueuedGossipBlock),
    RpcBlock(QueuedRpcBlock),
    IgnoredRpcBlock(IgnoredRpcBlock),
    Unaggregate(QueuedUnaggregate),
    Aggregate(QueuedAggregate),
    LightClientUpdate(QueuedLightClientUpdate),
    BackfillSync(QueuedBackfillBatch),
}

/// An Attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedUnaggregate {
    pub beacon_block_root: Hash256,
    pub process_fn: BlockingFn,
}

/// An aggregated attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedAggregate {
    pub beacon_block_root: Hash256,
    pub process_fn: BlockingFn,
}

/// A light client update for which the corresponding parent block was not seen while processing,
/// queued for later.
pub struct QueuedLightClientUpdate {
    pub parent_root: Hash256,
    pub process_fn: BlockingFn,
}

/// A block that arrived early and has been queued for later import.
pub struct QueuedGossipBlock {
    pub beacon_block_slot: Slot,
    pub beacon_block_root: Hash256,
    pub process_fn: AsyncFn,
}

/// A block that arrived for processing when the same block was being imported over gossip.
/// It is queued for later import.
pub struct QueuedRpcBlock {
    pub beacon_block_root: Hash256,
    /// Processes/imports the block.
    pub process_fn: AsyncFn,
    /// Ignores the block.
    pub ignore_fn: BlockingFn,
}

/// A block that arrived for processing when the same block was being imported over gossip.
/// It is queued for later import.
pub struct IgnoredRpcBlock {
    pub process_fn: BlockingFn,
}

/// A backfill batch work that has been queued for processing later.
pub struct QueuedBackfillBatch(pub AsyncFn);

impl<E: EthSpec> TryFrom<WorkEvent<E>> for QueuedBackfillBatch {
    type Error = WorkEvent<E>;

    fn try_from(event: WorkEvent<E>) -> Result<Self, WorkEvent<E>> {
        match event {
            WorkEvent {
                work: Work::ChainSegmentBackfill(process_fn),
                ..
            } => Ok(QueuedBackfillBatch(process_fn)),
            _ => Err(event),
        }
    }
}

impl<E: EthSpec> From<QueuedBackfillBatch> for WorkEvent<E> {
    fn from(queued_backfill_batch: QueuedBackfillBatch) -> WorkEvent<E> {
        WorkEvent {
            drop_during_sync: false,
            work: Work::ChainSegmentBackfill(queued_backfill_batch.0),
        }
    }
}

/// Unifies the different messages processed by the block delay queue.
enum InboundEvent {
    /// A gossip block that was queued for later processing and is ready for import.
    ReadyGossipBlock(QueuedGossipBlock),
    /// A rpc block that was queued because the same gossip block was being imported
    /// will now be retried for import.
    ReadyRpcBlock(QueuedRpcBlock),
    /// An aggregated or unaggregated attestation is ready for re-processing.
    ReadyAttestation(QueuedAttestationId),
    /// A light client update that is ready for re-processing.
    ReadyLightClientUpdate(QueuedLightClientUpdateId),
    /// A backfill batch that was queued is ready for processing.
    ReadyBackfillSync(QueuedBackfillBatch),
    /// A message sent to the `ReprocessQueue`
    Msg(ReprocessQueueMessage),
}

/// Manages scheduling works that need to be later re-processed.
struct ReprocessQueue<S> {
    /// Receiver of messages relevant to schedule works for reprocessing.
    work_reprocessing_rx: Receiver<ReprocessQueueMessage>,
    /// Sender of works once they become ready
    ready_work_tx: Sender<ReadyWork>,

    /* Queues */
    /// Queue to manage scheduled early blocks.
    gossip_block_delay_queue: DelayQueue<QueuedGossipBlock>,
    /// Queue to manage scheduled early blocks.
    rpc_block_delay_queue: DelayQueue<QueuedRpcBlock>,
    /// Queue to manage scheduled attestations.
    attestations_delay_queue: DelayQueue<QueuedAttestationId>,
    /// Queue to manage scheduled light client updates.
    lc_updates_delay_queue: DelayQueue<QueuedLightClientUpdateId>,

    /* Queued items */
    /// Queued blocks.
    queued_gossip_block_roots: HashSet<Hash256>,
    /// Queued aggregated attestations.
    queued_aggregates: FnvHashMap<usize, (QueuedAggregate, DelayKey)>,
    /// Queued attestations.
    queued_unaggregates: FnvHashMap<usize, (QueuedUnaggregate, DelayKey)>,
    /// Attestations (aggregated and unaggregated) per root.
    awaiting_attestations_per_root: HashMap<Hash256, Vec<QueuedAttestationId>>,
    /// Queued Light Client Updates.
    queued_lc_updates: FnvHashMap<usize, (QueuedLightClientUpdate, DelayKey)>,
    /// Light Client Updates per parent_root.
    awaiting_lc_updates_per_parent_root: HashMap<Hash256, Vec<QueuedLightClientUpdateId>>,
    /// Queued backfill batches
    queued_backfill_batches: Vec<QueuedBackfillBatch>,

    /* Aux */
    /// Next attestation id, used for both aggregated and unaggregated attestations
    next_attestation: usize,
    next_lc_update: usize,
    early_block_debounce: TimeLatch,
    rpc_block_debounce: TimeLatch,
    attestation_delay_debounce: TimeLatch,
    lc_update_delay_debounce: TimeLatch,
    next_backfill_batch_event: Option<Pin<Box<tokio::time::Sleep>>>,
    slot_clock: Arc<S>,
}

pub type QueuedLightClientUpdateId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueuedAttestationId {
    Aggregate(usize),
    Unaggregate(usize),
}

impl QueuedAggregate {
    pub fn beacon_block_root(&self) -> &Hash256 {
        &self.beacon_block_root
    }
}

impl QueuedUnaggregate {
    pub fn beacon_block_root(&self) -> &Hash256 {
        &self.beacon_block_root
    }
}

impl<S: SlotClock> Stream for ReprocessQueue<S> {
    type Item = InboundEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // NOTE: implementing `Stream` is not necessary but allows to maintain the future selection
        // order fine-grained and separate from the logic of handling each message, which is nice.

        // Poll for expired blocks *before* we try to process new blocks.
        //
        // The sequential nature of blockchains means it is generally better to try and import all
        // existing blocks before new ones.
        match self.gossip_block_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(queued_block)) => {
                return Poll::Ready(Some(InboundEvent::ReadyGossipBlock(
                    queued_block.into_inner(),
                )));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        match self.rpc_block_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(queued_block)) => {
                return Poll::Ready(Some(InboundEvent::ReadyRpcBlock(queued_block.into_inner())));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        match self.attestations_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(attestation_id)) => {
                return Poll::Ready(Some(InboundEvent::ReadyAttestation(
                    attestation_id.into_inner(),
                )));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        match self.lc_updates_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(lc_id)) => {
                return Poll::Ready(Some(InboundEvent::ReadyLightClientUpdate(
                    lc_id.into_inner(),
                )));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        if let Some(next_backfill_batch_event) = self.next_backfill_batch_event.as_mut() {
            match next_backfill_batch_event.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    let maybe_batch = self.queued_backfill_batches.pop();
                    self.recompute_next_backfill_batch_event();

                    if let Some(batch) = maybe_batch {
                        return Poll::Ready(Some(InboundEvent::ReadyBackfillSync(batch)));
                    }
                }
                Poll::Pending => (),
            }
        }

        // Last empty the messages channel.
        match self.work_reprocessing_rx.poll_recv(cx) {
            Poll::Ready(Some(message)) => return Poll::Ready(Some(InboundEvent::Msg(message))),
            Poll::Ready(None) | Poll::Pending => {}
        }

        Poll::Pending
    }
}

/// Starts the job that manages scheduling works that need re-processing. The returned `Sender`
/// gives the communicating channel to receive those works. Once a work is ready, it is sent back
/// via `ready_work_tx`.
pub fn spawn_reprocess_scheduler<S: SlotClock + 'static>(
    ready_work_tx: Sender<ReadyWork>,
    work_reprocessing_rx: Receiver<ReprocessQueueMessage>,
    executor: &TaskExecutor,
    slot_clock: Arc<S>,
    log: Logger,
    maximum_gossip_clock_disparity: Duration,
) -> Result<(), String> {
    // Sanity check
    if ADDITIONAL_QUEUED_BLOCK_DELAY >= maximum_gossip_clock_disparity {
        return Err("The block delay and gossip disparity don't match.".to_string());
    }
    let mut queue = ReprocessQueue::new(ready_work_tx, work_reprocessing_rx, slot_clock);

    executor.spawn(
        async move {
            while let Some(msg) = queue.next().await {
                queue.handle_message(msg, &log);
            }

            debug!(
                log,
                "Re-process queue stopped";
                "msg" => "shutting down"
            );
        },
        TASK_NAME,
    );
    Ok(())
}

impl<S: SlotClock> ReprocessQueue<S> {
    fn new(
        ready_work_tx: Sender<ReadyWork>,
        work_reprocessing_rx: Receiver<ReprocessQueueMessage>,
        slot_clock: Arc<S>,
    ) -> Self {
        ReprocessQueue {
            work_reprocessing_rx,
            ready_work_tx,
            gossip_block_delay_queue: DelayQueue::new(),
            rpc_block_delay_queue: DelayQueue::new(),
            attestations_delay_queue: DelayQueue::new(),
            lc_updates_delay_queue: DelayQueue::new(),
            queued_gossip_block_roots: HashSet::new(),
            queued_lc_updates: FnvHashMap::default(),
            queued_aggregates: FnvHashMap::default(),
            queued_unaggregates: FnvHashMap::default(),
            awaiting_attestations_per_root: HashMap::new(),
            awaiting_lc_updates_per_parent_root: HashMap::new(),
            queued_backfill_batches: Vec::new(),
            next_attestation: 0,
            next_lc_update: 0,
            early_block_debounce: TimeLatch::default(),
            rpc_block_debounce: TimeLatch::default(),
            attestation_delay_debounce: TimeLatch::default(),
            lc_update_delay_debounce: TimeLatch::default(),
            next_backfill_batch_event: None,
            slot_clock,
        }
    }

    fn handle_message(&mut self, msg: InboundEvent, log: &Logger) {
        use ReprocessQueueMessage::*;
        match msg {
            // Some block has been indicated as "early" and should be processed when the
            // appropriate slot arrives.
            InboundEvent::Msg(EarlyBlock(early_block)) => {
                let block_slot = early_block.beacon_block_slot;
                let block_root = early_block.beacon_block_root;

                // Don't add the same block to the queue twice. This prevents DoS attacks.
                if self.queued_gossip_block_roots.contains(&block_root) {
                    return;
                }

                if let Some(duration_till_slot) = self.slot_clock.duration_to_slot(block_slot) {
                    // Check to ensure this won't over-fill the queue.
                    if self.queued_gossip_block_roots.len() >= MAXIMUM_QUEUED_BLOCKS {
                        if self.early_block_debounce.elapsed() {
                            warn!(
                                log,
                                "Early blocks queue is full";
                                "queue_size" => MAXIMUM_QUEUED_BLOCKS,
                                "msg" => "check system clock"
                            );
                        }
                        // Drop the block.
                        return;
                    }

                    self.queued_gossip_block_roots.insert(block_root);
                    // Queue the block until the start of the appropriate slot, plus
                    // `ADDITIONAL_QUEUED_BLOCK_DELAY`.
                    self.gossip_block_delay_queue.insert(
                        early_block,
                        duration_till_slot + ADDITIONAL_QUEUED_BLOCK_DELAY,
                    );
                } else {
                    // If there is no duration till the next slot, check to see if the slot
                    // has already arrived. If it has already arrived, send it out for
                    // immediate processing.
                    //
                    // If we can't read the slot or the slot hasn't arrived, simply drop the
                    // block.
                    //
                    // This logic is slightly awkward since `SlotClock::duration_to_slot`
                    // doesn't distinguish between a slot that has already arrived and an
                    // error reading the slot clock.
                    if let Some(now) = self.slot_clock.now() {
                        if block_slot <= now
                            && self
                                .ready_work_tx
                                .try_send(ReadyWork::Block(early_block))
                                .is_err()
                        {
                            error!(
                                log,
                                "Failed to send block";
                            );
                        }
                    }
                }
            }
            // A rpc block arrived for processing at the same time when a gossip block
            // for the same block hash is being imported. We wait for `QUEUED_RPC_BLOCK_DELAY`
            // and then send the rpc block back for processing assuming the gossip import
            // has completed by then.
            InboundEvent::Msg(RpcBlock(rpc_block)) => {
                // Check to ensure this won't over-fill the queue.
                if self.rpc_block_delay_queue.len() >= MAXIMUM_QUEUED_BLOCKS {
                    if self.rpc_block_debounce.elapsed() {
                        warn!(
                            log,
                            "RPC blocks queue is full";
                            "queue_size" => MAXIMUM_QUEUED_BLOCKS,
                            "msg" => "check system clock"
                        );
                    }
                    // Return the block to the beacon processor signalling to
                    // ignore processing for this block
                    if self
                        .ready_work_tx
                        .try_send(ReadyWork::IgnoredRpcBlock(IgnoredRpcBlock {
                            process_fn: rpc_block.ignore_fn,
                        }))
                        .is_err()
                    {
                        error!(
                            log,
                            "Failed to send rpc block to beacon processor";
                        );
                    }
                    return;
                }

                // Queue the block for 1/3rd of a slot
                self.rpc_block_delay_queue
                    .insert(rpc_block, QUEUED_RPC_BLOCK_DELAY);
            }
            InboundEvent::ReadyRpcBlock(queued_rpc_block) => {
                debug!(
                    log,
                    "Sending rpc block for reprocessing";
                    "block_root" => %queued_rpc_block.beacon_block_root
                );
                if self
                    .ready_work_tx
                    .try_send(ReadyWork::RpcBlock(queued_rpc_block))
                    .is_err()
                {
                    error!(
                        log,
                        "Failed to send rpc block to beacon processor";
                    );
                }
            }
            InboundEvent::Msg(UnknownBlockAggregate(queued_aggregate)) => {
                if self.attestations_delay_queue.len() >= MAXIMUM_QUEUED_ATTESTATIONS {
                    if self.attestation_delay_debounce.elapsed() {
                        error!(
                            log,
                            "Aggregate attestation delay queue is full";
                            "queue_size" => MAXIMUM_QUEUED_ATTESTATIONS,
                            "msg" => "check system clock"
                        );
                    }
                    // Drop the attestation.
                    return;
                }

                let att_id = QueuedAttestationId::Aggregate(self.next_attestation);

                // Register the delay.
                let delay_key = self
                    .attestations_delay_queue
                    .insert(att_id, QUEUED_ATTESTATION_DELAY);

                // Register this attestation for the corresponding root.
                self.awaiting_attestations_per_root
                    .entry(*queued_aggregate.beacon_block_root())
                    .or_default()
                    .push(att_id);

                // Store the attestation and its info.
                self.queued_aggregates
                    .insert(self.next_attestation, (queued_aggregate, delay_key));

                self.next_attestation += 1;
            }
            InboundEvent::Msg(UnknownBlockUnaggregate(queued_unaggregate)) => {
                if self.attestations_delay_queue.len() >= MAXIMUM_QUEUED_ATTESTATIONS {
                    if self.attestation_delay_debounce.elapsed() {
                        error!(
                            log,
                            "Attestation delay queue is full";
                            "queue_size" => MAXIMUM_QUEUED_ATTESTATIONS,
                            "msg" => "check system clock"
                        );
                    }
                    // Drop the attestation.
                    return;
                }

                let att_id = QueuedAttestationId::Unaggregate(self.next_attestation);

                // Register the delay.
                let delay_key = self
                    .attestations_delay_queue
                    .insert(att_id, QUEUED_ATTESTATION_DELAY);

                // Register this attestation for the corresponding root.
                self.awaiting_attestations_per_root
                    .entry(*queued_unaggregate.beacon_block_root())
                    .or_default()
                    .push(att_id);

                // Store the attestation and its info.
                self.queued_unaggregates
                    .insert(self.next_attestation, (queued_unaggregate, delay_key));

                self.next_attestation += 1;
            }
            InboundEvent::Msg(UnknownLightClientOptimisticUpdate(
                queued_light_client_optimistic_update,
            )) => {
                if self.lc_updates_delay_queue.len() >= MAXIMUM_QUEUED_LIGHT_CLIENT_UPDATES {
                    if self.lc_update_delay_debounce.elapsed() {
                        error!(
                            log,
                            "Light client updates delay queue is full";
                            "queue_size" => MAXIMUM_QUEUED_LIGHT_CLIENT_UPDATES,
                            "msg" => "check system clock"
                        );
                    }
                    // Drop the light client update.
                    return;
                }

                let lc_id: QueuedLightClientUpdateId = self.next_lc_update;

                // Register the delay.
                let delay_key = self
                    .lc_updates_delay_queue
                    .insert(lc_id, QUEUED_LIGHT_CLIENT_UPDATE_DELAY);

                // Register the light client update for the corresponding root.
                self.awaiting_lc_updates_per_parent_root
                    .entry(queued_light_client_optimistic_update.parent_root)
                    .or_default()
                    .push(lc_id);

                // Store the light client update and its info.
                self.queued_lc_updates.insert(
                    self.next_lc_update,
                    (queued_light_client_optimistic_update, delay_key),
                );

                self.next_lc_update += 1;
            }
            InboundEvent::Msg(BlockImported {
                block_root,
                parent_root,
            }) => {
                // Unqueue the attestations we have for this root, if any.
                if let Some(queued_ids) = self.awaiting_attestations_per_root.remove(&block_root) {
                    let mut sent_count = 0;
                    let mut failed_to_send_count = 0;

                    for id in queued_ids {
                        metrics::inc_counter(
                            &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_ATTESTATIONS,
                        );

                        if let Some((work, delay_key)) = match id {
                            QueuedAttestationId::Aggregate(id) => self
                                .queued_aggregates
                                .remove(&id)
                                .map(|(aggregate, delay_key)| {
                                    (ReadyWork::Aggregate(aggregate), delay_key)
                                }),
                            QueuedAttestationId::Unaggregate(id) => self
                                .queued_unaggregates
                                .remove(&id)
                                .map(|(unaggregate, delay_key)| {
                                    (ReadyWork::Unaggregate(unaggregate), delay_key)
                                }),
                        } {
                            // Remove the delay.
                            self.attestations_delay_queue.remove(&delay_key);

                            // Send the work.
                            if self.ready_work_tx.try_send(work).is_err() {
                                failed_to_send_count += 1;
                            } else {
                                sent_count += 1;
                            }
                        } else {
                            // There is a mismatch between the attestation ids registered for this
                            // root and the queued attestations. This should never happen.
                            error!(
                                log,
                                "Unknown queued attestation for block root";
                                "block_root" => ?block_root,
                                "att_id" => ?id,
                            );
                        }
                    }

                    if failed_to_send_count > 0 {
                        error!(
                            log,
                            "Ignored scheduled attestation(s) for block";
                            "hint" => "system may be overloaded",
                            "parent_root" => ?parent_root,
                            "block_root" => ?block_root,
                            "failed_count" => failed_to_send_count,
                            "sent_count" => sent_count,
                        );
                    }
                }
            }
            InboundEvent::Msg(NewLightClientOptimisticUpdate { parent_root }) => {
                // Unqueue the light client optimistic updates we have for this root, if any.
                if let Some(queued_lc_id) = self
                    .awaiting_lc_updates_per_parent_root
                    .remove(&parent_root)
                {
                    debug!(
                        log,
                        "Dequeuing light client optimistic updates";
                        "parent_root" => %parent_root,
                        "count" => queued_lc_id.len(),
                    );

                    for lc_id in queued_lc_id {
                        metrics::inc_counter(
                            &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_OPTIMISTIC_UPDATES,
                        );
                        if let Some((work, delay_key)) = self.queued_lc_updates.remove(&lc_id).map(
                            |(light_client_optimistic_update, delay_key)| {
                                (
                                    ReadyWork::LightClientUpdate(light_client_optimistic_update),
                                    delay_key,
                                )
                            },
                        ) {
                            // Remove the delay
                            self.lc_updates_delay_queue.remove(&delay_key);

                            // Send the work
                            match self.ready_work_tx.try_send(work) {
                                Ok(_) => trace!(
                                    log,
                                    "reprocessing light client update sent";
                                ),
                                Err(_) => error!(
                                    log,
                                    "Failed to send scheduled light client update";
                                ),
                            }
                        } else {
                            // There is a mismatch between the light client update ids registered for this
                            // root and the queued light client updates. This should never happen.
                            error!(
                                log,
                                "Unknown queued light client update for parent root";
                                "parent_root" => ?parent_root,
                                "lc_id" => ?lc_id,
                            );
                        }
                    }
                }
            }
            InboundEvent::Msg(BackfillSync(queued_backfill_batch)) => {
                self.queued_backfill_batches
                    .insert(0, queued_backfill_batch);
                // only recompute if there is no `next_backfill_batch_event` already scheduled
                if self.next_backfill_batch_event.is_none() {
                    self.recompute_next_backfill_batch_event();
                }
            }
            // A block that was queued for later processing is now ready to be processed.
            InboundEvent::ReadyGossipBlock(ready_block) => {
                let block_root = ready_block.beacon_block_root;

                if !self.queued_gossip_block_roots.remove(&block_root) {
                    // Log an error to alert that we've made a bad assumption about how this
                    // program works, but still process the block anyway.
                    error!(
                        log,
                        "Unknown block in delay queue";
                        "block_root" => ?block_root
                    );
                }

                if self
                    .ready_work_tx
                    .try_send(ReadyWork::Block(ready_block))
                    .is_err()
                {
                    error!(
                        log,
                        "Failed to pop queued block";
                    );
                }
            }
            InboundEvent::ReadyAttestation(queued_id) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_EXPIRED_ATTESTATIONS,
                );

                if let Some((root, work)) = match queued_id {
                    QueuedAttestationId::Aggregate(id) => {
                        self.queued_aggregates
                            .remove(&id)
                            .map(|(aggregate, _delay_key)| {
                                (
                                    *aggregate.beacon_block_root(),
                                    ReadyWork::Aggregate(aggregate),
                                )
                            })
                    }
                    QueuedAttestationId::Unaggregate(id) => self
                        .queued_unaggregates
                        .remove(&id)
                        .map(|(unaggregate, _delay_key)| {
                            (
                                *unaggregate.beacon_block_root(),
                                ReadyWork::Unaggregate(unaggregate),
                            )
                        }),
                } {
                    if self.ready_work_tx.try_send(work).is_err() {
                        error!(
                            log,
                            "Ignored scheduled attestation";
                            "hint" => "system may be overloaded",
                            "beacon_block_root" => ?root
                        );
                    }

                    if let Some(queued_atts) = self.awaiting_attestations_per_root.get_mut(&root) {
                        if let Some(index) = queued_atts.iter().position(|&id| id == queued_id) {
                            queued_atts.swap_remove(index);
                        }
                    }
                }
            }
            InboundEvent::ReadyLightClientUpdate(queued_id) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_EXPIRED_OPTIMISTIC_UPDATES,
                );

                if let Some((parent_root, work)) = self.queued_lc_updates.remove(&queued_id).map(
                    |(queued_lc_update, _delay_key)| {
                        (
                            queued_lc_update.parent_root,
                            ReadyWork::LightClientUpdate(queued_lc_update),
                        )
                    },
                ) {
                    if self.ready_work_tx.try_send(work).is_err() {
                        error!(
                            log,
                            "Failed to send scheduled light client optimistic update";
                        );
                    }

                    if let Some(queued_lc_updates) = self
                        .awaiting_lc_updates_per_parent_root
                        .get_mut(&parent_root)
                    {
                        if let Some(index) =
                            queued_lc_updates.iter().position(|&id| id == queued_id)
                        {
                            queued_lc_updates.swap_remove(index);
                        }
                    }
                }
            }
            InboundEvent::ReadyBackfillSync(queued_backfill_batch) => {
                let millis_from_slot_start = self
                    .slot_clock
                    .millis_from_current_slot_start()
                    .map_or("null".to_string(), |duration| {
                        duration.as_millis().to_string()
                    });

                debug!(
                    log,
                    "Sending scheduled backfill work";
                    "millis_from_slot_start" => millis_from_slot_start
                );

                match self
                    .ready_work_tx
                    .try_send(ReadyWork::BackfillSync(queued_backfill_batch))
                {
                    // The message was sent successfully.
                    Ok(()) => (),
                    // The message was not sent, recover it from the returned `Err`.
                    Err(mpsc::error::TrySendError::Full(ReadyWork::BackfillSync(batch)))
                    | Err(mpsc::error::TrySendError::Closed(ReadyWork::BackfillSync(batch))) => {
                        error!(
                            log,
                            "Failed to send scheduled backfill work";
                            "info" => "sending work back to queue"
                        );
                        self.queued_backfill_batches.insert(0, batch);

                        // only recompute if there is no `next_backfill_batch_event` already scheduled
                        if self.next_backfill_batch_event.is_none() {
                            self.recompute_next_backfill_batch_event();
                        }
                    }
                    // The message was not sent and we didn't get the correct
                    // return result. This is a logic error.
                    _ => crit!(
                        log,
                        "Unexpected return from try_send error";
                    ),
                }
            }
        }

        metrics::set_gauge_vec(
            &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_TOTAL,
            &[GOSSIP_BLOCKS],
            self.gossip_block_delay_queue.len() as i64,
        );
        metrics::set_gauge_vec(
            &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_TOTAL,
            &[RPC_BLOCKS],
            self.rpc_block_delay_queue.len() as i64,
        );
        metrics::set_gauge_vec(
            &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_TOTAL,
            &[ATTESTATIONS],
            self.attestations_delay_queue.len() as i64,
        );
        metrics::set_gauge_vec(
            &metrics::BEACON_PROCESSOR_REPROCESSING_QUEUE_TOTAL,
            &[LIGHT_CLIENT_UPDATES],
            self.lc_updates_delay_queue.len() as i64,
        );
    }

    fn recompute_next_backfill_batch_event(&mut self) {
        // only recompute the `next_backfill_batch_event` if there are backfill batches in the queue
        if !self.queued_backfill_batches.is_empty() {
            self.next_backfill_batch_event = Some(Box::pin(tokio::time::sleep(
                ReprocessQueue::<S>::duration_until_next_backfill_batch_event(&self.slot_clock),
            )));
        } else {
            self.next_backfill_batch_event = None
        }
    }

    /// Returns duration until the next scheduled processing time. The schedule ensure that backfill
    /// processing is done in windows of time that aren't critical
    fn duration_until_next_backfill_batch_event(slot_clock: &S) -> Duration {
        let slot_duration = slot_clock.slot_duration();
        slot_clock
            .millis_from_current_slot_start()
            .and_then(|duration_from_slot_start| {
                BACKFILL_SCHEDULE_IN_SLOT
                    .into_iter()
                    // Convert fractions to seconds from slot start.
                    .map(|(multiplier, divisor)| (slot_duration / divisor) * multiplier)
                    .find_or_first(|&event_duration_from_slot_start| {
                        event_duration_from_slot_start > duration_from_slot_start
                    })
                    .map(|next_event_time| {
                        if duration_from_slot_start >= next_event_time {
                            // event is in the next slot, add duration to next slot
                            let duration_to_next_slot = slot_duration - duration_from_slot_start;
                            duration_to_next_slot + next_event_time
                        } else {
                            next_event_time - duration_from_slot_start
                        }
                    })
            })
            // If we can't read the slot clock, just wait another slot.
            .unwrap_or(slot_duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logging::test_logger;
    use slot_clock::{ManualSlotClock, TestingSlotClock};
    use std::ops::Add;
    use std::sync::Arc;
    use task_executor::test_utils::TestRuntime;

    #[test]
    fn backfill_processing_schedule_calculation() {
        let slot_duration = Duration::from_secs(12);
        let slot_clock = TestingSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);
        let current_slot_start = slot_clock.start_of(Slot::new(100)).unwrap();
        slot_clock.set_current_time(current_slot_start);

        let event_times = BACKFILL_SCHEDULE_IN_SLOT
            .map(|(multiplier, divisor)| (slot_duration / divisor) * multiplier);

        for &event_duration_from_slot_start in event_times.iter() {
            let duration_to_next_event =
                ReprocessQueue::<TestingSlotClock>::duration_until_next_backfill_batch_event(
                    &slot_clock,
                );

            let current_time = slot_clock.millis_from_current_slot_start().unwrap();

            assert_eq!(
                duration_to_next_event,
                event_duration_from_slot_start - current_time
            );

            slot_clock.set_current_time(current_slot_start + event_duration_from_slot_start)
        }

        // check for next event beyond the current slot
        let duration_to_next_slot = slot_clock.duration_to_next_slot().unwrap();
        let duration_to_next_event =
            ReprocessQueue::<TestingSlotClock>::duration_until_next_backfill_batch_event(
                &slot_clock,
            );
        assert_eq!(
            duration_to_next_event,
            duration_to_next_slot + event_times[0]
        );
    }

    // Regression test for issue #5504.
    // See: https://github.com/sigp/lighthouse/issues/5504#issuecomment-2050930045
    #[tokio::test]
    async fn backfill_schedule_failed_should_reschedule() {
        let runtime = TestRuntime::default();
        let log = test_logger();
        let (work_reprocessing_tx, work_reprocessing_rx) = mpsc::channel(1);
        let (ready_work_tx, mut ready_work_rx) = mpsc::channel(1);
        let slot_duration = 12;
        let slot_clock = Arc::new(testing_slot_clock(slot_duration));

        spawn_reprocess_scheduler(
            ready_work_tx.clone(),
            work_reprocessing_rx,
            &runtime.task_executor,
            slot_clock.clone(),
            log,
            Duration::from_millis(500),
        )
        .unwrap();

        // Pause time so it only advances manually
        tokio::time::pause();

        // Send some random work to `ready_work_tx` to fill up the capacity first.
        ready_work_tx
            .try_send(ReadyWork::IgnoredRpcBlock(IgnoredRpcBlock {
                process_fn: Box::new(|| {}),
            }))
            .unwrap();

        // Now queue a backfill sync batch.
        work_reprocessing_tx
            .try_send(ReprocessQueueMessage::BackfillSync(QueuedBackfillBatch(
                Box::pin(async {}),
            )))
            .unwrap();
        tokio::task::yield_now().await;

        // Advance the time by more than 1/2 the slot to trigger a scheduled backfill batch to be sent.
        // This should fail as the `ready_work` channel is at capacity, and it should be rescheduled.
        let duration_to_next_event =
            ReprocessQueue::duration_until_next_backfill_batch_event(slot_clock.as_ref());
        let one_ms = Duration::from_millis(1);
        advance_time(&slot_clock, duration_to_next_event.add(one_ms)).await;

        // Now drain the `ready_work` channel.
        assert!(matches!(
            ready_work_rx.try_recv(),
            Ok(ReadyWork::IgnoredRpcBlock { .. })
        ));
        assert!(ready_work_rx.try_recv().is_err());

        // Advance time again, and assert that the re-scheduled batch is successfully sent.
        let duration_to_next_event =
            ReprocessQueue::duration_until_next_backfill_batch_event(slot_clock.as_ref());
        advance_time(&slot_clock, duration_to_next_event.add(one_ms)).await;
        assert!(matches!(
            ready_work_rx.try_recv(),
            Ok(ReadyWork::BackfillSync { .. })
        ));
    }

    /// Advances slot clock and test clock time by the same duration.
    async fn advance_time(slot_clock: &ManualSlotClock, duration: Duration) {
        slot_clock.advance_time(duration);
        tokio::time::advance(duration).await;
        // NOTE: The `tokio::time::advance` fn actually calls `yield_now()` after advancing the
        // clock. Why do we need an extra `yield_now`?
        tokio::task::yield_now().await;
    }

    fn testing_slot_clock(slot_duration: u64) -> ManualSlotClock {
        TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(slot_duration),
        )
    }
}
