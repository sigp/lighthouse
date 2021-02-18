use super::MAX_DELAYED_BLOCK_QUEUE_LEN;
use beacon_chain::{BeaconChainTypes, GossipVerifiedBlock};
use eth2_libp2p::PeerId;
use futures::future::poll_fn;
use slog::{error, Logger};
use slot_clock::SlotClock;
use std::collections::HashSet;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::time::DelayQueue;

const TASK_NAME: &str = "beacon_processor_block_delay_queue";

/// Queue blocks for re-processing with an `ADDITIONAL_DELAY` after the slot starts. This is to
/// account for any slight drift in the system clock.
const ADDITIONAL_DELAY: Duration = Duration::from_millis(5);

pub struct QueuedBlock<T: BeaconChainTypes> {
    pub peer_id: PeerId,
    pub block: GossipVerifiedBlock<T>,
    pub seen_timestamp: Duration,
}

pub fn spawn_block_delay_queue<T: BeaconChainTypes>(
    ready_blocks_tx: Sender<QueuedBlock<T>>,
    executor: &TaskExecutor,
    slot_clock: T::SlotClock,
    log: Logger,
) -> Sender<QueuedBlock<T>> {
    let (early_blocks_tx, mut early_blocks_rx): (_, Receiver<QueuedBlock<_>>) =
        mpsc::channel(MAX_DELAYED_BLOCK_QUEUE_LEN);

    let queue_future = async move {
        let mut delay_queue = DelayQueue::new();
        let mut queued_block_roots = HashSet::new();

        loop {
            tokio::select! {
                opt = early_blocks_rx.recv() => {
                    if let Some(early_block) = opt {
                        let block_slot = early_block.block.block.slot();
                        let block_root = early_block.block.block_root;

                        // Don't add the same block to the queue twice. This prevents DoS attacks.
                        if queued_block_roots.contains(&block_root) {
                            continue;
                        }

                        if let Some(duration_till_slot) = slot_clock.duration_to_slot(block_slot) {
                            queued_block_roots.insert(block_root);
                            // Queue the block until the start of the appropriate slot, plus
                            // `ADDITIONAL_DELAY`.
                            delay_queue.insert(early_block, duration_till_slot + ADDITIONAL_DELAY);
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
                                if block_slot <= now {
                                    if ready_blocks_tx.try_send(early_block).is_err() {
                                        error!(
                                            log,
                                            "Failed to send block";
                                        );
                                    }
                                }
                            }
                        }
                    }
                },
                poll = poll_fn(|cx| delay_queue.poll_expired(cx)) => {
                    match poll {
                        Some(Ok(expired_block)) => {
                            let expired_block = expired_block.into_inner();
                            let block_root = expired_block.block.block_root;

                            if !queued_block_roots.remove(&block_root) {
                                error!(
                                    log,
                                    "Unknown block in delay queue";
                                    "block_root" => ?block_root
                                );
                            }

                            if ready_blocks_tx.try_send(expired_block).is_err() {
                                error!(
                                    log,
                                    "Failed to pop queued block";
                                );
                            }
                        }
                        Some(Err(e)) => error!(
                            log,
                            "Failed to poll block delay queue";
                            "e" => ?e
                        ),
                        None => (),     // Queue is exhausted, nothing ready.
                    }
                }
            }
        }
    };

    executor.spawn(queue_future, TASK_NAME);

    early_blocks_tx
}
