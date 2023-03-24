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
use super::MAX_SCHEDULED_WORK_QUEUE_LEN;
use crate::metrics;
use crate::sync::manager::BlockProcessType;
use beacon_chain::blob_verification::{AsBlock, BlockWrapper};
use beacon_chain::{BeaconChainTypes, GossipVerifiedBlock, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use fnv::FnvHashMap;
use futures::task::Poll;
use futures::{Stream, StreamExt};
use lighthouse_network::{MessageId, PeerId};
use logging::TimeLatch;
use slog::{crit, debug, error, trace, warn, Logger};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::task::Context;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::error::Error as TimeError;
use tokio_util::time::delay_queue::{DelayQueue, Key as DelayKey};
use types::{
    Attestation, EthSpec, Hash256, LightClientOptimisticUpdate, SignedAggregateAndProof, SubnetId,
};

const TASK_NAME: &str = "beacon_processor_reprocess_queue";
const GOSSIP_BLOCKS: &str = "gossip_blocks";
const RPC_BLOCKS: &str = "rpc_blocks";
const ATTESTATIONS: &str = "attestations";
const LIGHT_CLIENT_UPDATES: &str = "lc_updates";

/// Queue blocks for re-processing with an `ADDITIONAL_QUEUED_BLOCK_DELAY` after the slot starts.
/// This is to account for any slight drift in the system clock.
const ADDITIONAL_QUEUED_BLOCK_DELAY: Duration = Duration::from_millis(5);

/// For how long to queue aggregated and unaggregated attestations for re-processing.
pub const QUEUED_ATTESTATION_DELAY: Duration = Duration::from_secs(12);

/// For how long to queue light client updates for re-processing.
pub const QUEUED_LIGHT_CLIENT_UPDATE_DELAY: Duration = Duration::from_secs(12);

/// For how long to queue rpc blocks before sending them back for reprocessing.
pub const QUEUED_RPC_BLOCK_DELAY: Duration = Duration::from_secs(3);

/// Set an arbitrary upper-bound on the number of queued blocks to avoid DoS attacks. The fact that
/// we signature-verify blocks before putting them in the queue *should* protect against this, but
/// it's nice to have extra protection.
const MAXIMUM_QUEUED_BLOCKS: usize = 16;

/// How many attestations we keep before new ones get dropped.
const MAXIMUM_QUEUED_ATTESTATIONS: usize = 16_384;

/// How many light client updates we keep before new ones get dropped.
const MAXIMUM_QUEUED_LIGHT_CLIENT_UPDATES: usize = 128;

/// Messages that the scheduler can receive.
pub enum ReprocessQueueMessage<T: BeaconChainTypes> {
    /// A block that has been received early and we should queue for later processing.
    EarlyBlock(QueuedGossipBlock<T>),
    /// A gossip block for hash `X` is being imported, we should queue the rpc block for the same
    /// hash until the gossip block is imported.
    RpcBlock(QueuedRpcBlock<T::EthSpec>),
    /// A block that was successfully processed. We use this to handle attestations and light client updates
    /// for unknown blocks.
    BlockImported {
        block_root: Hash256,
        parent_root: Hash256,
    },
    /// An unaggregated attestation that references an unknown block.
    UnknownBlockUnaggregate(QueuedUnaggregate<T::EthSpec>),
    /// An aggregated attestation that references an unknown block.
    UnknownBlockAggregate(QueuedAggregate<T::EthSpec>),
    /// A light client optimistic update that references a parent root that has not been seen as a parent.
    UnknownLightClientOptimisticUpdate(QueuedLightClientUpdate<T::EthSpec>),
}

/// Events sent by the scheduler once they are ready for re-processing.
pub enum ReadyWork<T: BeaconChainTypes> {
    Block(QueuedGossipBlock<T>),
    RpcBlock(QueuedRpcBlock<T::EthSpec>),
    Unaggregate(QueuedUnaggregate<T::EthSpec>),
    Aggregate(QueuedAggregate<T::EthSpec>),
    LightClientUpdate(QueuedLightClientUpdate<T::EthSpec>),
}

/// An Attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedUnaggregate<T: EthSpec> {
    pub peer_id: PeerId,
    pub message_id: MessageId,
    pub attestation: Box<Attestation<T>>,
    pub subnet_id: SubnetId,
    pub should_import: bool,
    pub seen_timestamp: Duration,
}

/// An aggregated attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedAggregate<T: EthSpec> {
    pub peer_id: PeerId,
    pub message_id: MessageId,
    pub attestation: Box<SignedAggregateAndProof<T>>,
    pub seen_timestamp: Duration,
}

/// A light client update for which the corresponding parent block was not seen while processing,
/// queued for later.
pub struct QueuedLightClientUpdate<T: EthSpec> {
    pub peer_id: PeerId,
    pub message_id: MessageId,
    pub light_client_optimistic_update: Box<LightClientOptimisticUpdate<T>>,
    pub parent_root: Hash256,
    pub seen_timestamp: Duration,
}

/// A block that arrived early and has been queued for later import.
pub struct QueuedGossipBlock<T: BeaconChainTypes> {
    pub peer_id: PeerId,
    pub block: Box<GossipVerifiedBlock<T>>,
    pub seen_timestamp: Duration,
}

/// A block that arrived for processing when the same block was being imported over gossip.
/// It is queued for later import.
pub struct QueuedRpcBlock<T: EthSpec> {
    pub block_root: Hash256,
    pub block: BlockWrapper<T>,
    pub process_type: BlockProcessType,
    pub seen_timestamp: Duration,
    /// Indicates if the beacon chain should process this block or not.
    /// We use this to ignore block processing when rpc block queues are full.
    pub should_process: bool,
}

/// Unifies the different messages processed by the block delay queue.
enum InboundEvent<T: BeaconChainTypes> {
    /// A gossip block that was queued for later processing and is ready for import.
    ReadyGossipBlock(QueuedGossipBlock<T>),
    /// A rpc block that was queued because the same gossip block was being imported
    /// will now be retried for import.
    ReadyRpcBlock(QueuedRpcBlock<T::EthSpec>),
    /// An aggregated or unaggregated attestation is ready for re-processing.
    ReadyAttestation(QueuedAttestationId),
    /// A light client update that is ready for re-processing.
    ReadyLightClientUpdate(QueuedLightClientUpdateId),
    /// A `DelayQueue` returned an error.
    DelayQueueError(TimeError, &'static str),
    /// A message sent to the `ReprocessQueue`
    Msg(ReprocessQueueMessage<T>),
}

/// Manages scheduling works that need to be later re-processed.
struct ReprocessQueue<T: BeaconChainTypes> {
    /// Receiver of messages relevant to schedule works for reprocessing.
    work_reprocessing_rx: Receiver<ReprocessQueueMessage<T>>,
    /// Sender of works once they become ready
    ready_work_tx: Sender<ReadyWork<T>>,

    /* Queues */
    /// Queue to manage scheduled early blocks.
    gossip_block_delay_queue: DelayQueue<QueuedGossipBlock<T>>,
    /// Queue to manage scheduled early blocks.
    rpc_block_delay_queue: DelayQueue<QueuedRpcBlock<T::EthSpec>>,
    /// Queue to manage scheduled attestations.
    attestations_delay_queue: DelayQueue<QueuedAttestationId>,
    /// Queue to manage scheduled light client updates.
    lc_updates_delay_queue: DelayQueue<QueuedLightClientUpdateId>,

    /* Queued items */
    /// Queued blocks.
    queued_gossip_block_roots: HashSet<Hash256>,
    /// Queued aggregated attestations.
    queued_aggregates: FnvHashMap<usize, (QueuedAggregate<T::EthSpec>, DelayKey)>,
    /// Queued attestations.
    queued_unaggregates: FnvHashMap<usize, (QueuedUnaggregate<T::EthSpec>, DelayKey)>,
    /// Attestations (aggregated and unaggregated) per root.
    awaiting_attestations_per_root: HashMap<Hash256, Vec<QueuedAttestationId>>,
    /// Queued Light Client Updates.
    queued_lc_updates: FnvHashMap<usize, (QueuedLightClientUpdate<T::EthSpec>, DelayKey)>,
    /// Light Client Updates per parent_root.
    awaiting_lc_updates_per_parent_root: HashMap<Hash256, Vec<QueuedLightClientUpdateId>>,

    /* Aux */
    /// Next attestation id, used for both aggregated and unaggregated attestations
    next_attestation: usize,
    next_lc_update: usize,
    early_block_debounce: TimeLatch,
    rpc_block_debounce: TimeLatch,
    attestation_delay_debounce: TimeLatch,
    lc_update_delay_debounce: TimeLatch,
}

pub type QueuedLightClientUpdateId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueuedAttestationId {
    Aggregate(usize),
    Unaggregate(usize),
}

impl<T: EthSpec> QueuedAggregate<T> {
    pub fn beacon_block_root(&self) -> &Hash256 {
        &self.attestation.message.aggregate.data.beacon_block_root
    }
}

impl<T: EthSpec> QueuedUnaggregate<T> {
    pub fn beacon_block_root(&self) -> &Hash256 {
        &self.attestation.data.beacon_block_root
    }
}

impl<T: BeaconChainTypes> Stream for ReprocessQueue<T> {
    type Item = InboundEvent<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // NOTE: implementing `Stream` is not necessary but allows to maintain the future selection
        // order fine-grained and separate from the logic of handling each message, which is nice.

        // Poll for expired blocks *before* we try to process new blocks.
        //
        // The sequential nature of blockchains means it is generally better to try and import all
        // existing blocks before new ones.
        match self.gossip_block_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(queued_block))) => {
                return Poll::Ready(Some(InboundEvent::ReadyGossipBlock(
                    queued_block.into_inner(),
                )));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e, "gossip_block_queue")));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        match self.rpc_block_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(queued_block))) => {
                return Poll::Ready(Some(InboundEvent::ReadyRpcBlock(queued_block.into_inner())));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e, "rpc_block_queue")));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        match self.attestations_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(attestation_id))) => {
                return Poll::Ready(Some(InboundEvent::ReadyAttestation(
                    attestation_id.into_inner(),
                )));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e, "attestations_queue")));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        match self.lc_updates_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(lc_id))) => {
                return Poll::Ready(Some(InboundEvent::ReadyLightClientUpdate(
                    lc_id.into_inner(),
                )));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e, "lc_updates_queue")));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
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
pub fn spawn_reprocess_scheduler<T: BeaconChainTypes>(
    ready_work_tx: Sender<ReadyWork<T>>,
    executor: &TaskExecutor,
    slot_clock: T::SlotClock,
    log: Logger,
) -> Sender<ReprocessQueueMessage<T>> {
    let (work_reprocessing_tx, work_reprocessing_rx) = mpsc::channel(MAX_SCHEDULED_WORK_QUEUE_LEN);
    // Basic sanity check.
    assert!(ADDITIONAL_QUEUED_BLOCK_DELAY < MAXIMUM_GOSSIP_CLOCK_DISPARITY);

    let mut queue = ReprocessQueue {
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
        next_attestation: 0,
        next_lc_update: 0,
        early_block_debounce: TimeLatch::default(),
        rpc_block_debounce: TimeLatch::default(),
        attestation_delay_debounce: TimeLatch::default(),
        lc_update_delay_debounce: TimeLatch::default(),
    };

    executor.spawn(
        async move {
            while let Some(msg) = queue.next().await {
                queue.handle_message(msg, &slot_clock, &log);
            }

            debug!(
                log,
                "Re-process queue stopped";
                "msg" => "shutting down"
            );
        },
        TASK_NAME,
    );

    work_reprocessing_tx
}

impl<T: BeaconChainTypes> ReprocessQueue<T> {
    fn handle_message(&mut self, msg: InboundEvent<T>, slot_clock: &T::SlotClock, log: &Logger) {
        use ReprocessQueueMessage::*;
        match msg {
            // Some block has been indicated as "early" and should be processed when the
            // appropriate slot arrives.
            InboundEvent::Msg(EarlyBlock(early_block)) => {
                let block_slot = early_block.block.block.slot();
                let block_root = early_block.block.block_root;

                // Don't add the same block to the queue twice. This prevents DoS attacks.
                if self.queued_gossip_block_roots.contains(&block_root) {
                    return;
                }

                if let Some(duration_till_slot) = slot_clock.duration_to_slot(block_slot) {
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
                    if let Some(now) = slot_clock.now() {
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
            InboundEvent::Msg(RpcBlock(mut rpc_block)) => {
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
                    rpc_block.should_process = false;
                    if self
                        .ready_work_tx
                        .try_send(ReadyWork::RpcBlock(rpc_block))
                        .is_err()
                    {
                        error!(
                            log,
                            "Failed to send rpc block to beacon processor";
                        );
                    }
                    return;
                }

                // Queue the block for 1/4th of a slot
                self.rpc_block_delay_queue
                    .insert(rpc_block, QUEUED_RPC_BLOCK_DELAY);
            }
            InboundEvent::ReadyRpcBlock(queued_rpc_block) => {
                debug!(
                    log,
                    "Sending rpc block for reprocessing";
                    "block_root" => %queued_rpc_block.block_root
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
            // A block that was queued for later processing is now ready to be processed.
            InboundEvent::ReadyGossipBlock(ready_block) => {
                let block_root = ready_block.block.block_root;

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
            InboundEvent::DelayQueueError(e, queue_name) => {
                crit!(
                    log,
                    "Failed to poll queue";
                    "queue" => queue_name,
                    "e" => ?e
                )
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
}
