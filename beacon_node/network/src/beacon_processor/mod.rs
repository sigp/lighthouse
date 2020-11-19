//! Provides the `BeaconProcessor`, a multi-threaded processor for messages received on the network
//! that need to be processed by the `BeaconChain`.
//!
//! Uses `tokio` tasks (instead of raw threads) to provide the following tasks:
//!
//! - A "manager" task, which either spawns worker tasks or enqueues work.
//! - One or more "worker" tasks which perform time-intensive work on the `BeaconChain`.
//!
//! ## Purpose
//!
//! The purpose of the `BeaconProcessor` is to provide two things:
//!
//! 1. Moving long-running, blocking tasks off the main `tokio` executor.
//! 2. A fixed-length buffer for consensus messages.
//!
//! (1) ensures that we don't clog up the networking stack with long-running tasks, potentially
//! causing timeouts. (2) means that we can easily and explicitly reject messages when we're
//! overloaded and also distribute load across time.
//!
//! ## Detail
//!
//! There is a single "manager" thread who listens to two event channels. These events are either:
//!
//! - A new parcel of work (work event).
//! - Indication that a worker has finished a parcel of work (worker idle).
//!
//! Then, there is a maximum of `n` "worker" blocking threads, where `n` is the CPU count.
//!
//! Whenever the manager receives a new parcel of work, it is either:
//!
//! - Provided to a newly-spawned worker tasks (if we are not already at `n` workers).
//! - Added to a queue.
//!
//! Whenever the manager receives a notification that a worker has finished a parcel of work, it
//! checks the queues to see if there are more parcels of work that can be spawned in a new worker
//! task.

use crate::{metrics, service::NetworkMessage, sync::SyncMessage};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError};
use eth2_libp2p::{
    rpc::{BlocksByRangeRequest, BlocksByRootRequest, StatusMessage},
    MessageId, NetworkGlobals, PeerId, PeerRequestId,
};
use slog::{crit, debug, error, trace, warn, Logger};
use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use task_executor::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use types::{
    Attestation, AttesterSlashing, EthSpec, Hash256, ProposerSlashing, SignedAggregateAndProof,
    SignedBeaconBlock, SignedVoluntaryExit, SubnetId,
};

use worker::Worker;

mod worker;

pub use worker::ProcessId;

/// The maximum size of the channel for work events to the `BeaconProcessor`.
///
/// Setting this too low will cause consensus messages to be dropped.
pub const MAX_WORK_EVENT_QUEUE_LEN: usize = 16_384;

/// The maximum size of the channel for idle events to the `BeaconProcessor`.
///
/// Setting this too low will prevent new workers from being spawned. It *should* only need to be
/// set to the CPU count, but we set it high to be safe.
const MAX_IDLE_QUEUE_LEN: usize = 16_384;

/// The maximum number of queued `Attestation` objects that will be stored before we start dropping
/// them.
const MAX_UNAGGREGATED_ATTESTATION_QUEUE_LEN: usize = 16_384;

/// The maximum number of queued `SignedAggregateAndProof` objects that will be stored before we
/// start dropping them.
const MAX_AGGREGATED_ATTESTATION_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `SignedBeaconBlock` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_BLOCK_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `SignedVoluntaryExit` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_EXIT_QUEUE_LEN: usize = 4_096;

/// The maximum number of queued `ProposerSlashing` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_PROPOSER_SLASHING_QUEUE_LEN: usize = 4_096;

/// The maximum number of queued `AttesterSlashing` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_ATTESTER_SLASHING_QUEUE_LEN: usize = 4_096;

/// The maximum number of queued `SignedBeaconBlock` objects received from the network RPC that
/// will be stored before we start dropping them.
const MAX_RPC_BLOCK_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `Vec<SignedBeaconBlock>` objects received during syncing that will
/// be stored before we start dropping them.
const MAX_CHAIN_SEGMENT_QUEUE_LEN: usize = 64;

/// The maximum number of queued `StatusMessage` objects received from the network RPC that will be
/// stored before we start dropping them.
const MAX_STATUS_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `BlocksByRangeRequest` objects received from the network RPC that
/// will be stored before we start dropping them.
const MAX_BLOCKS_BY_RANGE_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `BlocksByRootRequest` objects received from the network RPC that
/// will be stored before we start dropping them.
const MAX_BLOCKS_BY_ROOTS_QUEUE_LEN: usize = 1_024;

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "beacon_processor_manager";
/// The name of the worker tokio tasks.
const WORKER_TASK_NAME: &str = "beacon_processor_worker";

/// The minimum interval between log messages indicating that a queue is full.
const LOG_DEBOUNCE_INTERVAL: Duration = Duration::from_secs(30);

/// Used to send/receive results from a rpc block import in a blocking task.
pub type BlockResultSender<E> = oneshot::Sender<Result<Hash256, BlockError<E>>>;
pub type BlockResultReceiver<E> = oneshot::Receiver<Result<Hash256, BlockError<E>>>;

/// A simple first-in-first-out queue with a maximum length.
struct FifoQueue<T> {
    queue: VecDeque<T>,
    max_length: usize,
}

impl<T> FifoQueue<T> {
    /// Create a new, empty queue with the given length.
    pub fn new(max_length: usize) -> Self {
        Self {
            queue: VecDeque::default(),
            max_length,
        }
    }

    /// Add a new item to the queue.
    ///
    /// Drops `item` if the queue is full.
    pub fn push(&mut self, item: T, item_desc: &str, log: &Logger) {
        if self.queue.len() == self.max_length {
            error!(
                log,
                "Work queue is full";
                "msg" => "the system has insufficient resources for load",
                "queue_len" => self.max_length,
                "queue" => item_desc,
            )
        } else {
            self.queue.push_back(item);
        }
    }

    /// Remove the next item from the queue.
    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    /// Returns the current length of the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

/// A simple last-in-first-out queue with a maximum length.
struct LifoQueue<T> {
    queue: VecDeque<T>,
    max_length: usize,
}

impl<T> LifoQueue<T> {
    /// Create a new, empty queue with the given length.
    pub fn new(max_length: usize) -> Self {
        Self {
            queue: VecDeque::default(),
            max_length,
        }
    }

    /// Add a new item to the front of the queue.
    ///
    /// If the queue is full, the item at the back of the queue is dropped.
    pub fn push(&mut self, item: T) {
        if self.queue.len() == self.max_length {
            self.queue.pop_back();
        }
        self.queue.push_front(item);
    }

    /// Remove the next item from the queue.
    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    /// Returns `true` if the queue is full.
    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.max_length
    }

    /// Returns the current length of the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

/// An event to be processed by the manager task.
#[derive(Debug)]
pub struct WorkEvent<E: EthSpec> {
    drop_during_sync: bool,
    work: Work<E>,
}

impl<E: EthSpec> WorkEvent<E> {
    /// Create a new `Work` event for some unaggregated attestation.
    pub fn unaggregated_attestation(
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Attestation<E>,
        subnet_id: SubnetId,
        should_import: bool,
    ) -> Self {
        Self {
            drop_during_sync: true,
            work: Work::GossipAttestation {
                message_id,
                peer_id,
                attestation: Box::new(attestation),
                subnet_id,
                should_import,
            },
        }
    }

    /// Create a new `Work` event for some aggregated attestation.
    pub fn aggregated_attestation(
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: SignedAggregateAndProof<E>,
    ) -> Self {
        Self {
            drop_during_sync: true,
            work: Work::GossipAggregate {
                message_id,
                peer_id,
                aggregate: Box::new(aggregate),
            },
        }
    }

    /// Create a new `Work` event for some block.
    pub fn gossip_beacon_block(
        message_id: MessageId,
        peer_id: PeerId,
        block: Box<SignedBeaconBlock<E>>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipBlock {
                message_id,
                peer_id,
                block,
            },
        }
    }

    /// Create a new `Work` event for some exit.
    pub fn gossip_voluntary_exit(
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipVoluntaryExit {
                message_id,
                peer_id,
                voluntary_exit,
            },
        }
    }

    /// Create a new `Work` event for some proposer slashing.
    pub fn gossip_proposer_slashing(
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipProposerSlashing {
                message_id,
                peer_id,
                proposer_slashing,
            },
        }
    }

    /// Create a new `Work` event for some attester slashing.
    pub fn gossip_attester_slashing(
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<E>>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipAttesterSlashing {
                message_id,
                peer_id,
                attester_slashing,
            },
        }
    }

    /// Create a new `Work` event for some block, where the result from computation (if any) is
    /// sent to the other side of `result_tx`.
    pub fn rpc_beacon_block(block: Box<SignedBeaconBlock<E>>) -> (Self, BlockResultReceiver<E>) {
        let (result_tx, result_rx) = oneshot::channel();
        let event = Self {
            drop_during_sync: false,
            work: Work::RpcBlock { block, result_tx },
        };
        (event, result_rx)
    }

    /// Create a new work event to import `blocks` as a beacon chain segment.
    pub fn chain_segment(process_id: ProcessId, blocks: Vec<SignedBeaconBlock<E>>) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::ChainSegment { process_id, blocks },
        }
    }

    /// Create a new work event to process `StatusMessage`s from the RPC network.
    pub fn status_message(peer_id: PeerId, message: StatusMessage) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::Status { peer_id, message },
        }
    }

    /// Create a new work event to process `BlocksByRangeRequest`s from the RPC network.
    pub fn blocks_by_range_request(
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRangeRequest,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::BlocksByRangeRequest {
                peer_id,
                request_id,
                request,
            },
        }
    }

    /// Create a new work event to process `BlocksByRootRequest`s from the RPC network.
    pub fn blocks_by_roots_request(
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::BlocksByRootsRequest {
                peer_id,
                request_id,
                request,
            },
        }
    }

    /// Get a `str` representation of the type of work this `WorkEvent` contains.
    pub fn work_type(&self) -> &'static str {
        self.work.str_id()
    }
}

/// A consensus message (or multiple) from the network that requires processing.
#[derive(Debug)]
pub enum Work<E: EthSpec> {
    GossipAttestation {
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Box<Attestation<E>>,
        subnet_id: SubnetId,
        should_import: bool,
    },
    GossipAggregate {
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: Box<SignedAggregateAndProof<E>>,
    },
    GossipBlock {
        message_id: MessageId,
        peer_id: PeerId,
        block: Box<SignedBeaconBlock<E>>,
    },
    GossipVoluntaryExit {
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    },
    GossipProposerSlashing {
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    },
    GossipAttesterSlashing {
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<E>>,
    },
    RpcBlock {
        block: Box<SignedBeaconBlock<E>>,
        result_tx: BlockResultSender<E>,
    },
    ChainSegment {
        process_id: ProcessId,
        blocks: Vec<SignedBeaconBlock<E>>,
    },
    Status {
        peer_id: PeerId,
        message: StatusMessage,
    },
    BlocksByRangeRequest {
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRangeRequest,
    },
    BlocksByRootsRequest {
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    },
}

impl<E: EthSpec> Work<E> {
    /// Provides a `&str` that uniquely identifies each enum variant.
    fn str_id(&self) -> &'static str {
        match self {
            Work::GossipAttestation { .. } => "gossip_attestation",
            Work::GossipAggregate { .. } => "gossip_aggregate",
            Work::GossipBlock { .. } => "gossip_block",
            Work::GossipVoluntaryExit { .. } => "gossip_voluntary_exit",
            Work::GossipProposerSlashing { .. } => "gossip_proposer_slashing",
            Work::GossipAttesterSlashing { .. } => "gossip_attester_slashing",
            Work::RpcBlock { .. } => "rpc_block",
            Work::ChainSegment { .. } => "chain_segment",
            Work::Status { .. } => "status_processing",
            Work::BlocksByRangeRequest { .. } => "blocks_by_range_request",
            Work::BlocksByRootsRequest { .. } => "blocks_by_roots_request",
        }
    }
}

/// Provides de-bounce functionality for logging.
#[derive(Default)]
struct TimeLatch(Option<Instant>);

impl TimeLatch {
    /// Only returns true once every `LOG_DEBOUNCE_INTERVAL`.
    fn elapsed(&mut self) -> bool {
        let now = Instant::now();

        let is_elapsed = self.0.map_or(false, |elapse_time| now > elapse_time);

        if is_elapsed || self.0.is_none() {
            self.0 = Some(now + LOG_DEBOUNCE_INTERVAL);
        }

        is_elapsed
    }
}

/// A mutli-threaded processor for messages received on the network
/// that need to be processed by the `BeaconChain`
///
/// See module level documentation for more information.
pub struct BeaconProcessor<T: BeaconChainTypes> {
    pub beacon_chain: Weak<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub executor: TaskExecutor,
    pub max_workers: usize,
    pub current_workers: usize,
    pub log: Logger,
}

impl<T: BeaconChainTypes> BeaconProcessor<T> {
    /// Spawns the "manager" task which checks the receiver end of the returned `Sender` for
    /// messages which contain some new work which will be:
    ///
    /// - Performed immediately, if a worker is available.
    /// - Queued for later processing, if no worker is currently available.
    ///
    /// Only `self.max_workers` will ever be spawned at one time. Each worker is a `tokio` task
    /// started with `spawn_blocking`.
    pub fn spawn_manager(mut self, mut event_rx: mpsc::Receiver<WorkEvent<T::EthSpec>>) {
        let (idle_tx, mut idle_rx) = mpsc::channel::<()>(MAX_IDLE_QUEUE_LEN);

        // Using LIFO queues for attestations since validator profits rely upon getting fresh
        // attestations into blocks. Additionally, later attestations contain more information than
        // earlier ones, so we consider them more valuable.
        let mut aggregate_queue = LifoQueue::new(MAX_AGGREGATED_ATTESTATION_QUEUE_LEN);
        let mut aggregate_debounce = TimeLatch::default();
        let mut attestation_queue = LifoQueue::new(MAX_UNAGGREGATED_ATTESTATION_QUEUE_LEN);
        let mut attestation_debounce = TimeLatch::default();

        // Using a FIFO queue for voluntary exits since it prevents exit censoring. I don't have
        // a strong feeling about queue type for exits.
        let mut gossip_voluntary_exit_queue = FifoQueue::new(MAX_GOSSIP_EXIT_QUEUE_LEN);

        // Using a FIFO queue for slashing to prevent people from flushing their slashings from the
        // queues with lots of junk messages.
        let mut gossip_proposer_slashing_queue =
            FifoQueue::new(MAX_GOSSIP_PROPOSER_SLASHING_QUEUE_LEN);
        let mut gossip_attester_slashing_queue =
            FifoQueue::new(MAX_GOSSIP_ATTESTER_SLASHING_QUEUE_LEN);

        // Using a FIFO queue since blocks need to be imported sequentially.
        let mut rpc_block_queue = FifoQueue::new(MAX_RPC_BLOCK_QUEUE_LEN);
        let mut chain_segment_queue = FifoQueue::new(MAX_CHAIN_SEGMENT_QUEUE_LEN);
        let mut gossip_block_queue = FifoQueue::new(MAX_GOSSIP_BLOCK_QUEUE_LEN);

        let mut status_queue = FifoQueue::new(MAX_STATUS_QUEUE_LEN);
        let mut bbrange_queue = FifoQueue::new(MAX_BLOCKS_BY_RANGE_QUEUE_LEN);
        let mut bbroots_queue = FifoQueue::new(MAX_BLOCKS_BY_ROOTS_QUEUE_LEN);

        let executor = self.executor.clone();

        // The manager future will run on the core executor and delegate tasks to worker
        // threads on the blocking executor.
        let manager_future = async move {
            loop {
                // Listen to both the event and idle channels, acting on whichever is ready
                // first.
                //
                // Set `work_event = Some(event)` if there is new work to be done. Otherwise sets
                // `event = None` if it was a worker becoming idle.
                let work_event = tokio::select! {
                    // A worker has finished some work.
                    new_idle_opt = idle_rx.recv() => {
                        if new_idle_opt.is_some() {
                            self.current_workers = self.current_workers.saturating_sub(1);
                            None
                        } else {
                            // Exit if all idle senders have been dropped.
                            //
                            // This shouldn't happen since this function holds a sender.
                            crit!(
                                self.log,
                                "Gossip processor stopped";
                                "msg" => "all idle senders dropped"
                            );
                            break
                        }
                    },
                    // There is a new piece of work to be handled.
                    new_work_event_opt = event_rx.recv() => {
                        if let Some(new_work_event) = new_work_event_opt {
                            Some(new_work_event)
                        } else {
                            // Exit if all event senders have been dropped.
                            //
                            // This should happen when the client shuts down.
                            debug!(
                                self.log,
                                "Gossip processor stopped";
                                "msg" => "all event senders dropped"
                            );
                            break
                        }
                    }
                };

                let _event_timer =
                    metrics::start_timer(&metrics::BEACON_PROCESSOR_EVENT_HANDLING_SECONDS);
                if let Some(event) = &work_event {
                    metrics::inc_counter_vec(
                        &metrics::BEACON_PROCESSOR_WORK_EVENTS_RX_COUNT,
                        &[event.work.str_id()],
                    );
                } else {
                    metrics::inc_counter(&metrics::BEACON_PROCESSOR_IDLE_EVENTS_TOTAL);
                }

                let can_spawn = self.current_workers < self.max_workers;
                let drop_during_sync = work_event
                    .as_ref()
                    .map_or(false, |event| event.drop_during_sync);

                match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    //
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        // Check for chain segments first, they're the most efficient way to get
                        // blocks into the system.
                        if let Some(item) = chain_segment_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        // Check sync blocks before gossip blocks, since we've already explicitly
                        // requested these blocks.
                        } else if let Some(item) = rpc_block_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        // Check gossip blocks before gossip attestations, since a block might be
                        // required to verify some attestations.
                        } else if let Some(item) = gossip_block_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        // Check the aggregates, *then* the unaggregates since we assume that
                        // aggregates are more valuable to local validators and effectively give us
                        // more information with less signature verification time.
                        } else if let Some(item) = aggregate_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        } else if let Some(item) = attestation_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        // Check RPC methods next. Status messages are needed for sync so
                        // prioritize them over syncing requests from other peers (BlocksByRange
                        // and BlocksByRoot)
                        } else if let Some(item) = status_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        } else if let Some(item) = bbrange_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        } else if let Some(item) = bbroots_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        // Check slashings after all other consensus messages so we prioritize
                        // following head.
                        //
                        // Check attester slashings before proposer slashings since they have the
                        // potential to slash multiple validators at once.
                        } else if let Some(item) = gossip_attester_slashing_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        } else if let Some(item) = gossip_proposer_slashing_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        // Check exits last since our validators don't get rewards from them.
                        } else if let Some(item) = gossip_voluntary_exit_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        }
                    }
                    // There is no new work event and we are unable to spawn a new worker.
                    //
                    // I cannot see any good reason why this would happen.
                    None => {
                        warn!(
                            self.log,
                            "Unexpected gossip processor condition";
                            "msg" => "no new work and cannot spawn worker"
                        );
                    }
                    // The chain is syncing and this event should be dropped during sync.
                    Some(work_event)
                        if self.network_globals.sync_state.read().is_syncing()
                            && drop_during_sync =>
                    {
                        let work_id = work_event.work.str_id();
                        metrics::inc_counter_vec(
                            &metrics::BEACON_PROCESSOR_WORK_EVENTS_IGNORED_COUNT,
                            &[work_id],
                        );
                        trace!(
                            self.log,
                            "Gossip processor skipping work";
                            "msg" => "chain is syncing",
                            "work_id" => work_id
                        );
                    }
                    // There is a new work event and the chain is not syncing. Process it.
                    Some(WorkEvent { work, .. }) => {
                        let work_id = work.str_id();
                        match work {
                            _ if can_spawn => self.spawn_worker(idle_tx.clone(), work),
                            Work::GossipAttestation { .. } => attestation_queue.push(work),
                            Work::GossipAggregate { .. } => aggregate_queue.push(work),
                            Work::GossipBlock { .. } => {
                                gossip_block_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipVoluntaryExit { .. } => {
                                gossip_voluntary_exit_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipProposerSlashing { .. } => {
                                gossip_proposer_slashing_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipAttesterSlashing { .. } => {
                                gossip_attester_slashing_queue.push(work, work_id, &self.log)
                            }
                            Work::RpcBlock { .. } => rpc_block_queue.push(work, work_id, &self.log),
                            Work::ChainSegment { .. } => {
                                chain_segment_queue.push(work, work_id, &self.log)
                            }
                            Work::Status { .. } => status_queue.push(work, work_id, &self.log),
                            Work::BlocksByRangeRequest { .. } => {
                                bbrange_queue.push(work, work_id, &self.log)
                            }
                            Work::BlocksByRootsRequest { .. } => {
                                bbroots_queue.push(work, work_id, &self.log)
                            }
                        }
                    }
                }

                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_WORKERS_ACTIVE_TOTAL,
                    self.current_workers as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_QUEUE_TOTAL,
                    attestation_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_QUEUE_TOTAL,
                    aggregate_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_QUEUE_TOTAL,
                    gossip_block_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_RPC_BLOCK_QUEUE_TOTAL,
                    rpc_block_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_QUEUE_TOTAL,
                    chain_segment_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_EXIT_QUEUE_TOTAL,
                    gossip_voluntary_exit_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_PROPOSER_SLASHING_QUEUE_TOTAL,
                    gossip_proposer_slashing_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_ATTESTER_SLASHING_QUEUE_TOTAL,
                    gossip_attester_slashing_queue.len() as i64,
                );

                if aggregate_queue.is_full() && aggregate_debounce.elapsed() {
                    error!(
                        self.log,
                        "Aggregate attestation queue full";
                        "msg" => "the system has insufficient resources for load",
                        "queue_len" => aggregate_queue.max_length,
                    )
                }

                if attestation_queue.is_full() && attestation_debounce.elapsed() {
                    error!(
                        self.log,
                        "Attestation queue full";
                        "msg" => "the system has insufficient resources for load",
                        "queue_len" => attestation_queue.max_length,
                    )
                }
            }
        };

        // Spawn on the core executor.
        executor.spawn(manager_future, MANAGER_TASK_NAME);
    }

    /// Spawns a blocking worker thread to process some `Work`.
    ///
    /// Sends an message on `idle_tx` when the work is complete and the task is stopping.
    fn spawn_worker(&mut self, idle_tx: mpsc::Sender<()>, work: Work<T::EthSpec>) {
        // Wrap the `idle_tx` in a struct that will fire the idle message whenever it is dropped.
        //
        // This helps ensure that the worker is always freed in the case of an early exit or panic.
        // As such, this instantiation should happen as early in the function as possible.
        let send_idle_on_drop = SendOnDrop {
            tx: idle_tx,
            log: self.log.clone(),
        };

        let work_id = work.str_id();
        let worker_timer =
            metrics::start_timer_vec(&metrics::BEACON_PROCESSOR_WORKER_TIME, &[work_id]);
        metrics::inc_counter(&metrics::BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL);
        metrics::inc_counter_vec(
            &metrics::BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT,
            &[work.str_id()],
        );

        let worker_id = self.current_workers;
        self.current_workers = self.current_workers.saturating_add(1);

        let chain = if let Some(chain) = self.beacon_chain.upgrade() {
            chain
        } else {
            debug!(
                self.log,
                "Beacon chain dropped, shutting down";
            );
            return;
        };

        let log = self.log.clone();
        let executor = self.executor.clone();

        let worker = Worker {
            chain,
            network_tx: self.network_tx.clone(),
            sync_tx: self.sync_tx.clone(),
            log: self.log.clone(),
        };

        trace!(
            self.log,
            "Spawning beacon processor worker";
            "work" => work_id,
            "worker" => worker_id,
        );

        executor.spawn_blocking(
            move || {
                let _worker_timer = worker_timer;

                match work {
                    /*
                     * Unaggregated attestation verification.
                     */
                    Work::GossipAttestation {
                        message_id,
                        peer_id,
                        attestation,
                        subnet_id,
                        should_import,
                    } => worker.process_gossip_attestation(
                        message_id,
                        peer_id,
                        *attestation,
                        subnet_id,
                        should_import,
                    ),
                    /*
                     * Aggregated attestation verification.
                     */
                    Work::GossipAggregate {
                        message_id,
                        peer_id,
                        aggregate,
                    } => worker.process_gossip_aggregate(message_id, peer_id, *aggregate),
                    /*
                     * Verification for beacon blocks received on gossip.
                     */
                    Work::GossipBlock {
                        message_id,
                        peer_id,
                        block,
                    } => worker.process_gossip_block(message_id, peer_id, *block),
                    /*
                     * Voluntary exits received on gossip.
                     */
                    Work::GossipVoluntaryExit {
                        message_id,
                        peer_id,
                        voluntary_exit,
                    } => worker.process_gossip_voluntary_exit(message_id, peer_id, *voluntary_exit),
                    /*
                     * Proposer slashings received on gossip.
                     */
                    Work::GossipProposerSlashing {
                        message_id,
                        peer_id,
                        proposer_slashing,
                    } => worker.process_gossip_proposer_slashing(
                        message_id,
                        peer_id,
                        *proposer_slashing,
                    ),
                    /*
                     * Attester slashings received on gossip.
                     */
                    Work::GossipAttesterSlashing {
                        message_id,
                        peer_id,
                        attester_slashing,
                    } => worker.process_gossip_attester_slashing(
                        message_id,
                        peer_id,
                        *attester_slashing,
                    ),
                    /*
                     * Verification for beacon blocks received during syncing via RPC.
                     */
                    Work::RpcBlock { block, result_tx } => {
                        worker.process_rpc_block(*block, result_tx)
                    }
                    /*
                     * Verification for a chain segment (multiple blocks).
                     */
                    Work::ChainSegment { process_id, blocks } => {
                        worker.process_chain_segment(process_id, blocks)
                    }
                    /*
                     * Processing of Status Messages.
                     */
                    Work::Status { peer_id, message } => worker.process_status(peer_id, message),
                    /*
                     * Processing of range syncing requests from other peers.
                     */
                    Work::BlocksByRangeRequest {
                        peer_id,
                        request_id,
                        request,
                    } => worker.handle_blocks_by_range_request(peer_id, request_id, request),
                    /*
                     * Processing of blocks by roots requests from other peers.
                     */
                    Work::BlocksByRootsRequest {
                        peer_id,
                        request_id,
                        request,
                    } => worker.handle_blocks_by_root_request(peer_id, request_id, request),
                };

                trace!(
                    log,
                    "Beacon processor worker done";
                    "work" => work_id,
                    "worker" => worker_id,
                );

                // This explicit `drop` is used to remind the programmer that this variable must
                // not be dropped until the worker is complete. Dropping it early will cause the
                // worker to be marked as "free" and cause an over-spawning of workers.
                drop(send_idle_on_drop);
            },
            WORKER_TASK_NAME,
        );
    }
}

/// This struct will send a message on `self.tx` when it is dropped. An error will be logged on
/// `self.log` if the send fails (this happens when the node is shutting down).
///
/// ## Purpose
///
/// This is useful for ensuring that a worker-freed message is still sent if a worker panics.
///
/// The Rust docs for `Drop` state that `Drop` is called during an unwind in a panic:
///
/// https://doc.rust-lang.org/std/ops/trait.Drop.html#panics
pub struct SendOnDrop {
    tx: mpsc::Sender<()>,
    log: Logger,
}

impl Drop for SendOnDrop {
    fn drop(&mut self) {
        if let Err(e) = self.tx.try_send(()) {
            warn!(
                self.log,
                "Unable to free worker";
                "msg" => "did not free worker, shutdown may be underway",
                "error" => e.to_string()
            )
        }
    }
}
