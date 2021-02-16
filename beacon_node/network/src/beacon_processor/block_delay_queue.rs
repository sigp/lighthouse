use super::MAX_DELAYED_BLOCK_QUEUE_LEN;
use beacon_chain::{BeaconChainTypes, GossipVerifiedBlock};
use eth2_libp2p::PeerId;
use futures::future::poll_fn;
use slog::{error, Logger};
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, Sender};
use tokio_util::time::DelayQueue;

const TASK_NAME: &str = "beacon_processor_block_delay_queue";

pub struct QueuedBlock<T: BeaconChainTypes> {
    pub peer_id: PeerId,
    pub block: GossipVerifiedBlock<T>,
    pub seen_timestamp: Duration,
}

pub fn spawn_block_delay_queue<T: BeaconChainTypes>(
    ready_blocks_tx: Sender<QueuedBlock<T>>,
    executor: &TaskExecutor,
    log: Logger,
) -> Sender<QueuedBlock<T>> {
    let (early_blocks_tx, mut early_blocks_rx) = mpsc::channel(MAX_DELAYED_BLOCK_QUEUE_LEN);

    let queue_future = async move {
        let mut delay_queue = DelayQueue::new();

        loop {
            tokio::select! {
                opt = early_blocks_rx.recv() => {
                    if let Some(early_block) = opt {
                        // TODO: fix duration
                        delay_queue.insert(early_block, Duration::from_secs(1));
                    }
                },
                poll = poll_fn(|cx| delay_queue.poll_expired(cx)) => {
                    match poll {
                        Some(Ok(expired_block)) => {
                            if ready_blocks_tx.try_send(expired_block.into_inner()).is_err() {
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

/*
pub struct BlockDelayQueue<T: BeaconChainTypes> {
    delay_queue: DelayQueue<GossipVerifiedBlock<T>>,
    early_blocks_rx: Receiver<GossipVerifiedBlock<T>>,
    ready_blocks_tx: Sender<GossipVerifiedBlock<T>>,
    log: Logger,
}

impl<T: BeaconChainTypes> Future for BlockDelayQueue<T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Attempt to exhaust all blocks that are ready for processing.
            match self.delay_queue.poll_expired(cx) {
                Poll::Ready(Some(Ok(expired_block))) => {
                    if let Err(_) = self.ready_blocks_tx.try_send(expired_block.into_inner()) {
                        error!(
                            self.log,
                            "Failed to pop block delay queue";
                        );
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(
                        self.log,
                        "Failed to poll block delay queue";
                        "e" => ?e
                    );
                    break;
                }
                _ => break,
            }
        }

        // Clear the incoming queue of blocks that need to be delayed.
        loop {
            match <Receiver<_> as Stream>::poll_next(self.early_blocks_rx, cx) {
                Poll::Ready(Some(early_block)) => {
                    let delay = Duration::from_secs(1); // TODO: fix this.
                    self.delay_queue.insert(early_block, delay);
                }
            }
        }
    }
}
*/
