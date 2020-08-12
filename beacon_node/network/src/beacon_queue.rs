use crate::service::NetworkMessage;
use beacon_chain::BeaconChainTypes;
use eth2_libp2p::{
    rpc::{RPCError, RequestId},
    MessageId, NetworkGlobals, PeerId, PeerRequestId, PubsubMessage, Request, Response,
};
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;
use types::{Attestation, EthSpec, SignedBeaconBlock};

// TODO: set this better.
const MAX_WORK_QUEUE_LEN: usize = 16_384;
const MAX_GOSSIP_BLOCK_QUEUE_LEN: usize = 1_024;
const TASK_NAME: &str = "beacon_gossip_processor";

struct QueueItem<T> {
    message_id: MessageId,
    peer_id: PeerId,
    item: T,
}

struct Queue<T> {
    queue: VecDeque<QueueItem<T>>,
    max_length: usize,
}

impl<T> Queue<T> {
    pub fn new(max_length: usize) -> Self {
        Self {
            queue: VecDeque::default(),
            max_length,
        }
    }

    pub fn push(&mut self, item: QueueItem<T>) {
        if self.queue.len() == self.max_length {
            self.queue.pop_back();
        }
        self.queue.push_front(item);
    }

    pub fn pop(&mut self) -> Option<QueueItem<T>> {
        self.queue.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn has_items(&self) -> bool {
        !self.queue.is_empty()
    }
}

pub struct BeaconGossipQueue<T: BeaconChainTypes> {
    /// A channel to the network service to allow for gossip propagation.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    /// Queued gossip blocks.
    blocks: Queue<SignedBeaconBlock<T::EthSpec>>,
    /// Queued gossip unaggregated attestations.
    attestations: Queue<Attestation<T::EthSpec>>,
}

#[derive(Debug, PartialEq)]
pub enum Event<E: EthSpec> {
    WorkerIdle,
    Work {
        message_id: MessageId,
        peer_id: PeerId,
        work: Work<E>,
    },
}

impl<E: EthSpec> Event<E> {
    pub fn is_work(&self) -> bool {
        match self {
            Event::WorkerIdle => false,
            Event::Work { .. } => true,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Work<E: EthSpec> {
    Block(SignedBeaconBlock<E>),
}

pub struct BeaconGossipProcessor<T: BeaconChainTypes> {
    network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    executor: environment::TaskExecutor,
    max_workers: usize,
}

impl<T: BeaconChainTypes> BeaconGossipProcessor<T> {
    pub fn spawn(self) -> mpsc::Sender<Event<T::EthSpec>> {
        let (event_tx, mut event_rx) = mpsc::channel::<Event<T::EthSpec>>(MAX_WORK_QUEUE_LEN);
        let mut block_queue: Queue<SignedBeaconBlock<T::EthSpec>> =
            Queue::new(MAX_GOSSIP_BLOCK_QUEUE_LEN);
        let current_workers = AtomicUsize::default();
        let max_workers = self.max_workers;

        self.executor.spawn(
            async move {
                while let Some(event) = event_rx.recv().await {
                    let should_spawn = current_workers
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current_workers| {
                            Some(current_workers + 1)
                                // Don't update the variable if it will set us above max workers.
                                .filter(|workers| *workers <= max_workers)
                                // Don't update the variable if there's nothing to do.
                                .filter(|_| event.is_work() || !block_queue.is_empty())
                        })
                        // `fetch_update` only returns `Ok` if the value was updated.
                        .is_ok();

                    match event {
                        Event::WorkerIdle if should_spawn => {
                            if let Some(block) = block_queue.pop() {
                                todo!("create block task")
                            }
                        }
                        Event::WorkerIdle => {}
                        Event::Work {
                            message_id,
                            peer_id,
                            work,
                        } => match work {
                            Work::Block(block) if should_spawn => todo!("create block task"),
                            Work::Block(block) => block_queue.push(QueueItem {
                                message_id,
                                peer_id,
                                item: block,
                            }),
                        },
                    }
                }
            },
            "beacon_gossip_processor",
        );

        event_tx
    }
}

/*
pub async fn spawn<T: BeaconChainTypes>(
    work_tx: mpsc::UnboundedSender<Work>,
    mut work_rx: mpsc::UnboundedReceiver<Work>,
    network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    beacon_queue: RwLock<BeaconGossipQueue<T>>,
    current_workers: AtomicUsize,
    max_workers: usize,
) {
    let beacon_queue
}

pub struct QueueManager<T: BeaconChainTypes> {
    /// A channel to the network service to allow for gossip propagation.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    /// Queued unaggregated attestations.
    unaggregated_queue: VecDeque<QueuedItem<Attestation<T::EthSpec>>>,
}
*/
