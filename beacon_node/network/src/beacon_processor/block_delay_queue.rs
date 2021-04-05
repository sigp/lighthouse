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
use beacon_chain::types::Hash256;
use beacon_chain::{BeaconChainTypes, GossipVerifiedBlock};
use eth2_libp2p::PeerId;
use futures::stream::{Stream, StreamExt};
use futures::task::Poll;
use slog::{crit, debug, error, Logger};
use slot_clock::SlotClock;
use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::task::Context;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::error::Error as TimeError;
use tokio_util::time::DelayQueue;

const TASK_NAME: &str = "beacon_processor_block_delay_queue";

/// Queue blocks for re-processing with an `ADDITIONAL_DELAY` after the slot starts. This is to
/// account for any slight drift in the system clock.
const ADDITIONAL_DELAY: Duration = Duration::from_millis(5);

/// Set an arbitrary upper-bound on the number of queued blocks to avoid DoS attacks. The fact that
/// we signature-verify blocks before putting them in the queue *should* protect against this, but
/// it's nice to have extra protection.
const MAXIMUM_QUEUED_BLOCKS: usize = 16;

/// Messages that the scheduler can receive.
pub enum ReprocessSchedulerMessage<T: BeaconChainTypes> {
    /// A block that has been received early that we should queue for later processing.
    EarlyBlock(QueuedBlock<T>),
    /// A block that was succesfully processed. We use this to handle attestations for unknown
    /// blocks.
    BlockProcessed(Hash256),
    UnknownBlockAttestation,
    UnknownBlockAggregate,
}

pub enum ReadyWork<T: BeaconChainTypes> {
    Block(QueuedBlock<T>),
    Attestation,
    Aggregate,
}

/// A block that arrived early and has been queued for later import.
pub struct QueuedBlock<T: BeaconChainTypes> {
    pub peer_id: PeerId,
    pub block: GossipVerifiedBlock<T>,
    pub seen_timestamp: Duration,
}

/// Unifies the different messages processed by the block delay queue.
enum InboundEvent<T: BeaconChainTypes> {
    /// A block that has been received early that we should queue for later processing.
    EarlyBlock(QueuedBlock<T>),
    /// A block that was queued for later processing and is ready for import.
    ReadyBlock(QueuedBlock<T>),
    /// The `DelayQueue` returned an error.
    DelayQueueError(TimeError),
}

/// Combines the `DelayQueue` and `Receiver` streams into a single stream.
///
//struct has a similar purpose to `tokio::select!`, however it allows for more fine-grained
/// control (specifically in the ordering of event processing).
struct InboundEvents<T: BeaconChainTypes> {
    pub delay_queue: DelayQueue<QueuedBlock<T>>,
    /// When several works are ready simultaneously, they are queued to be sent back.
    ready_works: VecDeque<ReadyWork<T>>,
    /// Receiver of messages relevant to schedule works for reprocessing.
    work_reprocessing_rx: Receiver<ReprocessSchedulerMessage<T>>,
}

impl<T: BeaconChainTypes> Stream for InboundEvents<T> {
    type Item = InboundEvent<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll for expired blocks *before* we try to process new blocks.
        //
        // The sequential nature of blockchains means it is generally better to try and import all
        // existing blocks before new ones.
        match self.delay_queue.poll_expired(cx) {
            Poll::Ready(Some(Ok(queued_block))) => {
                return Poll::Ready(Some(InboundEvent::ReadyBlock(queued_block.into_inner())));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Some(InboundEvent::DelayQueueError(e)));
            }
            // `Poll::Ready(None)` means that there are no more entries in the delay queue and we
            // will continue to get this result until something else is added into the queue.
            Poll::Ready(None) | Poll::Pending => (),
        }

        match self.work_reprocessing_rx.poll_recv(cx) {
            Poll::Ready(Some(queued_block)) => {
                return Poll::Ready(Some(InboundEvent::EarlyBlock(queued_block)));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
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
) -> Sender<ReprocessSchedulerMessage<T>> {
    let (work_reprocessing_tx, work_reprocessing_rx) = mpsc::channel(MAX_DELAYED_BLOCK_QUEUE_LEN);

    let queue_future =
        work_reprocessing_scheduler(work_reprocessing_rx, ready_work_tx, slot_clock, log);

    executor.spawn(queue_future, TASK_NAME);

    work_reprocessing_tx
}

async fn work_reprocessing_scheduler<T: BeaconChainTypes>(
    work_reprocessing_rx: Receiver<ReprocessSchedulerMessage<T>>,
    ready_work_tx: Sender<ReadyWork<T>>,
    slot_clock: T::SlotClock,
    log: Logger,
) {
    let mut queued_block_roots = HashSet::new();

    let mut inbound_events = InboundEvents {
        work_reprocessing_rx,
        ready_works: VecDeque::new(), // TODO: bound this
        delay_queue: DelayQueue::new(),
    };

    loop {
        match inbound_events.next().await {
            // Some block has been indicated as "early" and should be processed when the
            // appropriate slot arrives.
            Some(InboundEvent::EarlyBlock(early_block)) => {
                let block_slot = early_block.block.block.slot();
                let block_root = early_block.block.block_root;

                // Don't add the same block to the queue twice. This prevents DoS attacks.
                if queued_block_roots.contains(&block_root) {
                    continue;
                }

                if let Some(duration_till_slot) = slot_clock.duration_to_slot(block_slot) {
                    // Check to ensure this won't over-fill the queue.
                    if queued_block_roots.len() >= MAXIMUM_QUEUED_BLOCKS {
                        error!(
                            log,
                            "Early blocks queue is full";
                            "queue_size" => MAXIMUM_QUEUED_BLOCKS,
                            "msg" => "check system clock"
                            );
                        // Drop the block.
                        continue;
                    }

                    queued_block_roots.insert(block_root);
                    // Queue the block until the start of the appropriate slot, plus
                    // `ADDITIONAL_DELAY`.
                    inbound_events
                        .delay_queue
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
                    if let Some(now) = slot_clock.now() {
                        if block_slot <= now && ready_work_tx.try_send(early_block).is_err() {
                            error!(
                                log,
                                "Failed to send block";
                                );
                        }
                    }
                }
            }
            // A block that was queued for later processing is now ready to be processed.
            Some(InboundEvent::ReadyBlock(ready_block)) => {
                let block_root = ready_block.block.block_root;

                if !queued_block_roots.remove(&block_root) {
                    // Log an error to alert that we've made a bad assumption about how this
                    // program works, but still process the block anyway.
                    error!(
                        log,
                        "Unknown block in delay queue";
                        "block_root" => ?block_root
                        );
                }

                if ready_work_tx.try_send(ready_block).is_err() {
                    error!(
                        log,
                        "Failed to pop queued block";
                        );
                }
            }
            Some(InboundEvent::DelayQueueError(e)) => crit!(
                log,
                "Failed to poll block delay queue";
                "e" => ?e
                ),
            None => {
                debug!(
                    log,
                    "Block delay queue stopped";
                    "msg" => "shutting down"
                    );
                break;
            }
        }
    }
}
