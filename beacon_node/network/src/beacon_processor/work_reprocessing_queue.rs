//! Provides a mechanism which queues blocks for later processing when they arrive too early.
//!
//! When the `beacon_processor::Worker` imports a block that is acceptably early (i.e., within the
//! gossip propagation tolerance) it will send it to this queue where it will be placed in a
//! `DelayQueue` until the slot arrives. Once the block has been determined to be ready, it will be
//! sent back out on a channel to be processed by the `BeaconProcessor` again.
//!
//! There is the edge-case where the slot arrives before this queue manages to process it. In that
//! case, the block will be sent off for immediate processing (skipping the `DelayQueue`).
use super::MAX_DELAYED_BLOCK_QUEUE_LEN;
use beacon_chain::{BeaconChainTypes, GossipVerifiedBlock};
use eth2_libp2p::{MessageId, PeerId};
use fnv::FnvHashMap;
use futures::task::Poll;
use futures::{Stream, StreamExt};
use slog::{crit, debug, error, Logger};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::task::Context;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::error::Error as TimeError;
use tokio_util::time::DelayQueue;
use types::{Attestation, EthSpec, Hash256, SignedAggregateAndProof, SubnetId};

const TASK_NAME: &str = "beacon_processor_block_delay_queue";

/// Queue blocks for re-processing with an `ADDITIONAL_DELAY` after the slot starts. This is to
/// account for any slight drift in the system clock.
const ADDITIONAL_DELAY: Duration = Duration::from_millis(5);

/// Set an arbitrary upper-bound on the number of queued blocks to avoid DoS attacks. The fact that
/// we signature-verify blocks before putting them in the queue *should* protect against this, but
/// it's nice to have extra protection.
const MAXIMUM_QUEUED_BLOCKS: usize = 16;

/// Messages that the scheduler can receive.
pub enum ReprocessQueueMessage<T: BeaconChainTypes> {
    /// A block that has been received early and we should queue for later processing.
    EarlyBlock(QueuedBlock<T>),
    /// A block that was succesfully processed. We use this to handle attestations for unknown
    /// blocks.
    BlockImported(Hash256),
    UnknownBlockUnaggregate(QueuedUnaggregate<T::EthSpec>),
    UnknownBlockAggregate(QueuedAggregate<T::EthSpec>),
}

/// Events sent by the scheduler once they are ready for re-processing.
pub enum ReadyWork<T: BeaconChainTypes> {
    Block(QueuedBlock<T>),
    Attestation(QueuedUnaggregate<T::EthSpec>),
    Aggregate(QueuedAggregate<T::EthSpec>),
}

/// An Attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedUnaggregate<T: EthSpec> {
    pub peer_id: PeerId,
    pub message_id: MessageId,
    pub attestation: Attestation<T>,
    pub subnet_id: SubnetId,
    pub should_import: bool,
    pub seen_timestamp: Duration,
}

/// An aggregated attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedAggregate<T: EthSpec> {
    pub peer_id: PeerId,
    pub message_id: MessageId,
    pub attestation: SignedAggregateAndProof<T>,
    pub seen_timestamp: Duration,
}

/// A block that arrived early and has been queued for later import.
pub struct QueuedBlock<T: BeaconChainTypes> {
    pub peer_id: PeerId,
    pub block: GossipVerifiedBlock<T>,
    pub seen_timestamp: Duration,
}

/// Unifies the different messages processed by the block delay queue.
enum InboundEvent<T: BeaconChainTypes> {
    /// A block that was queued for later processing and is ready for import.
    ReadyBlock(QueuedBlock<T>),
    /// An aggregated or unaggreated attestation is ready for re-processing.
    ReadyAttestation(QueuedAttestationId),
    /// A `DelayQueue` returned an error.
    DelayQueueError(TimeError, &'static str),
    /// A message sent to the `ReprocessQueue`
    Msg(ReprocessQueueMessage<T>),
}

/// Combines the `DelayQueue` and `Receiver` streams into a single stream.
/// struct has a similar purpose to `tokio::select!`, however it allows for more fine-grained
/// control (specifically in the ordering of event processing).
// TODO: update docs
struct ReprocessQueue<T: BeaconChainTypes> {
    /// Receiver of messages relevant to schedule works for reprocessing.
    work_reprocessing_rx: Receiver<ReprocessQueueMessage<T>>,
    /// Sender of works once they become ready
    ready_work_tx: Sender<ReadyWork<T>>,

    /* Queues */
    /// Queue to manage scheduled early blocks.
    block_delay_queue: DelayQueue<QueuedBlock<T>>,
    /// Queue to manage scheduled aggregated attestations.
    aggregate_delay_queue: DelayQueue<usize>,
    /// Queue to manage scheduled attestations.
    attestations_delay_queue: DelayQueue<usize>,

    /* Queued items */
    /// Queued blocks.
    queued_block_roots: HashSet<Hash256>,
    /// Queued aggreated attestations.
    queued_aggregates: FnvHashMap<usize, QueuedAggregate<T::EthSpec>>,
    /// Queued attestations.
    queued_attestations: FnvHashMap<usize, QueuedUnaggregate<T::EthSpec>>,
    /// Attestations (aggreated and unaggreated) per root.
    awaiting_attestations_per_root: HashMap<Hash256, VecDeque<QueuedAttestationId>>,

    /* Aux */
    /// Next attestation id, used for both aggreated and unaggreated attestations
    next_attestation: usize,

    slot_clock: T::SlotClock,

    log: Logger,
}

enum QueuedAttestationId {
    Aggregate(usize),
    Unaggregate(usize),
}

impl<T: BeaconChainTypes> Stream for ReprocessQueue<T> {
    type Item = InboundEvent<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll for expired blocks *before* we try to process new blocks.
        //
        // The sequential nature of blockchains means it is generally better to try and import all
        // existing blocks before new ones.
        match self.block_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(queued_block))) => {
                return Poll::Ready(Some(InboundEvent::ReadyBlock(queued_block.into_inner())));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e, "block_queue")));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        // Next get the aggregates, since these should be more useful.
        match self.aggregate_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(aggregate_id))) => {
                return Poll::Ready(Some(InboundEvent::ReadyAttestation(
                    QueuedAttestationId::Aggregate(aggregate_id.into_inner()),
                )));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e, "aggregates_queue")));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        // Next get the unaggregates.
        match self.attestations_delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(attestation_id))) => {
                return Poll::Ready(Some(InboundEvent::ReadyAttestation(
                    QueuedAttestationId::Unaggregate(attestation_id.into_inner()),
                )));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e, "unaggregates_queue")));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        // First empty the messages channel to ensure that when we start unqueuing attestations for
        // each root, we have as many as temporarily possible. This mitigates excesive hashing and
        // heap allocs.
        match self.work_reprocessing_rx.poll_recv(cx) {
            Poll::Ready(Some(message)) => return Poll::Ready(Some(InboundEvent::Msg(message))),
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {}
        }

        Poll::Pending
    }
}

/// Starts the job that manages scheduling works that need re-processing. The returned `Sender`
/// gives the communicating channel to receive those works. Once a work is ready, send them back
/// out via `ready_work_tx`.
pub fn spawn_reprocess_scheduler<T: BeaconChainTypes>(
    ready_work_tx: Sender<ReadyWork<T>>,
    executor: &TaskExecutor,
    slot_clock: T::SlotClock,
    log: Logger,
) -> Sender<ReprocessQueueMessage<T>> {
    let (work_reprocessing_tx, work_reprocessing_rx) = mpsc::channel(MAX_DELAYED_BLOCK_QUEUE_LEN);

    let mut queue = ReprocessQueue {
        work_reprocessing_rx,
        ready_work_tx,
        block_delay_queue: DelayQueue::new(),
        aggregate_delay_queue: DelayQueue::new(),
        attestations_delay_queue: DelayQueue::new(),
        queued_block_roots: HashSet::new(),
        queued_aggregates: FnvHashMap::default(),
        queued_attestations: FnvHashMap::default(),
        awaiting_attestations_per_root: HashMap::new(),
        next_attestation: 0,
        slot_clock,
        log,
    };

    executor.spawn(
        async move {
            loop {
                let msg = queue.next().await;
                queue.handle_message(msg);
            }
        },
        TASK_NAME,
    );

    work_reprocessing_tx
}

impl<T: BeaconChainTypes> ReprocessQueue<T> {
    fn handle_message(&mut self, msg: Option<InboundEvent<T>>) {
        use ReprocessQueueMessage::*;
        match msg {
            // Some block has been indicated as "early" and should be processed when the
            // appropriate slot arrives.
            Some(InboundEvent::Msg(EarlyBlock(early_block))) => {
                let block_slot = early_block.block.block.slot();
                let block_root = early_block.block.block_root;

                // Don't add the same block to the queue twice. This prevents DoS attacks.
                if self.queued_block_roots.contains(&block_root) {
                    return;
                }

                if let Some(duration_till_slot) = self.slot_clock.duration_to_slot(block_slot) {
                    // Check to ensure this won't over-fill the queue.
                    if self.queued_block_roots.len() >= MAXIMUM_QUEUED_BLOCKS {
                        error!(
                        self.log,
                        "Early blocks queue is full";
                        "queue_size" => MAXIMUM_QUEUED_BLOCKS,
                        "msg" => "check system clock"
                        );
                        // Drop the block.
                        return;
                    }

                    self.queued_block_roots.insert(block_root);
                    // Queue the block until the start of the appropriate slot, plus
                    // `ADDITIONAL_DELAY`.
                    self.block_delay_queue
                        .insert(early_block, duration_till_slot + ADDITIONAL_DELAY);
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
                            self.log,
                            "Failed to send block";
                            );
                        }
                    }
                }
            }
            Some(InboundEvent::Msg(UnknownBlockAggregate(queued_aggregate))) => {}
            Some(InboundEvent::Msg(UnknownBlockUnaggregate(queued_unaggregate))) => {}
            Some(InboundEvent::Msg(BlockImported(root))) => {}
            // A block that was queued for later processing is now ready to be processed.
            Some(InboundEvent::ReadyBlock(ready_block)) => {
                let block_root = ready_block.block.block_root;

                if !self.queued_block_roots.remove(&block_root) {
                    // Log an error to alert that we've made a bad assumption about how this
                    // program works, but still process the block anyway.
                    error!(
                    self.log,
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
                    self.log,
                    "Failed to pop queued block";
                    );
                }
            }
            Some(InboundEvent::DelayQueueError(e, queue_name)) => {
                crit!(
                self.log,
                "Failed to poll queue";
                "queue" => queue_name,
                "e" => ?e
                )
            }
            Some(InboundEvent::ReadyAttestation(_id)) => {}
            None => {
                debug!(
                self.log,
                "Block delay queue stopped";
                "msg" => "shutting down"
                );
                return;
            }
        }
    }
}
