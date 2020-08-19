//! Provides the `BeaconProcessor`, a mutli-threaded processor for messages received on the network
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
//! Whenever the manager receives a new parcel of work, it either:
//!
//! - Provided to a newly-spawned worker tasks (if we are not already at `n` workers).
//! - Added to a queue.
//!
//! Whenever the manager receives a notification that a worker has finished a parcel of work, it
//! checks the queues to see if there are more parcels of work that can be spawned in a new worker
//! task.

use crate::{metrics, service::NetworkMessage, sync::SyncMessage};
use beacon_chain::{
    attestation_verification::Error as AttnError, BeaconChain, BeaconChainError, BeaconChainTypes,
    BlockError, ForkChoiceError,
};
use chain_segment::handle_chain_segment;
use environment::TaskExecutor;
use eth2_libp2p::{MessageId, NetworkGlobals, PeerId};
use slog::{crit, debug, error, info, trace, warn, Logger};
use ssz::Encode;
use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use types::{Attestation, EthSpec, Hash256, SignedAggregateAndProof, SignedBeaconBlock, SubnetId};

mod chain_segment;

pub use chain_segment::ProcessId;

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

/// The maximum number of queued `SignedBeaconBlock` objects received from the network RPC that
/// will be stored before we start dropping them.
const MAX_RPC_BLOCK_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `Vec<SignedBeaconBlock>` objects received during syncing that will
/// be stored before we start dropping them.
const MAX_CHAIN_SEGMENT_QUEUE_LEN: usize = 64;

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "beacon_gossip_processor_manager";
/// The name of the worker tokio tasks.
const WORKER_TASK_NAME: &str = "beacon_gossip_processor_worker";

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
                "Block queue full";
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
    RpcBlock {
        block: Box<SignedBeaconBlock<E>>,
        result_tx: BlockResultSender<E>,
    },
    ChainSegment {
        process_id: ProcessId,
        blocks: Vec<SignedBeaconBlock<E>>,
    },
}

impl<E: EthSpec> Work<E> {
    /// Provides a `&str` that uniquely identifies each enum variant.
    fn str_id(&self) -> &'static str {
        match self {
            Work::GossipAttestation { .. } => "gossip_attestation",
            Work::GossipAggregate { .. } => "gossip_aggregate",
            Work::GossipBlock { .. } => "gossip_block",
            Work::RpcBlock { .. } => "rpc_block",
            Work::ChainSegment { .. } => "chain_segment",
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

        let mut aggregate_queue = LifoQueue::new(MAX_AGGREGATED_ATTESTATION_QUEUE_LEN);
        let mut aggregate_debounce = TimeLatch::default();

        let mut attestation_queue = LifoQueue::new(MAX_UNAGGREGATED_ATTESTATION_QUEUE_LEN);
        let mut attestation_debounce = TimeLatch::default();

        let mut gossip_block_queue = FifoQueue::new(MAX_GOSSIP_BLOCK_QUEUE_LEN);

        let mut rpc_block_queue = FifoQueue::new(MAX_RPC_BLOCK_QUEUE_LEN);

        let mut chain_segment_queue = FifoQueue::new(MAX_CHAIN_SEGMENT_QUEUE_LEN);

        let executor = self.executor.clone();

        // The manager future will run on the non-blocking executor and delegate tasks to worker
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
                        // Check the aggregates, *then* the unaggregates
                        // since we assume that aggregates are more valuable to local validators
                        // and effectively give us more information with less signature
                        // verification time.
                        } else if let Some(item) = aggregate_queue.pop() {
                            self.spawn_worker(idle_tx.clone(), item);
                        } else if let Some(item) = attestation_queue.pop() {
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
                            Work::RpcBlock { .. } => rpc_block_queue.push(work, work_id, &self.log),
                            Work::ChainSegment { .. } => {
                                chain_segment_queue.push(work, work_id, &self.log)
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

        // Spawn on the non-blocking executor.
        executor.spawn(manager_future, MANAGER_TASK_NAME);
    }

    /// Spawns a blocking worker thread to process some `Work`.
    ///
    /// Sends an message on `idle_tx` when the work is complete and the task is stopping.
    fn spawn_worker(&mut self, mut idle_tx: mpsc::Sender<()>, work: Work<T::EthSpec>) {
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

        let network_tx = self.network_tx.clone();
        let sync_tx = self.sync_tx.clone();
        let log = self.log.clone();
        let executor = self.executor.clone();

        trace!(
            self.log,
            "Spawning beacon processor worker";
            "work" => work_id,
            "worker" => worker_id,
        );

        executor.spawn_blocking(
            move || {
                let _worker_timer = worker_timer;
                let inner_log = log.clone();

                // We use this closure pattern to avoid using a `return` that prevents the
                // `idle_tx` message from sending.
                let handler = || {
                    let log = inner_log.clone();
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
                        } => {
                            let beacon_block_root = attestation.data.beacon_block_root;

                            let attestation = match chain
                                .verify_unaggregated_attestation_for_gossip(*attestation, subnet_id)
                            {
                                Ok(attestation) => attestation,
                                Err(e) => {
                                    handle_attestation_verification_failure(
                                        &log,
                                        sync_tx,
                                        peer_id,
                                        beacon_block_root,
                                        "unaggregated",
                                        e,
                                    );
                                    return;
                                }
                            };

                            // Indicate to the `Network` service that this message is valid and can be
                            // propagated on the gossip network.
                            propagate_gossip_message(network_tx, message_id, peer_id.clone(), &log);

                            if !should_import {
                                return;
                            }

                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_VERIFIED_TOTAL,
                            );

                            if let Err(e) = chain.apply_attestation_to_fork_choice(&attestation) {
                                match e {
                                    BeaconChainError::ForkChoiceError(
                                        ForkChoiceError::InvalidAttestation(e),
                                    ) => debug!(
                                        log,
                                        "Attestation invalid for fork choice";
                                        "reason" => format!("{:?}", e),
                                        "peer" => peer_id.to_string(),
                                        "beacon_block_root" => format!("{:?}", beacon_block_root)
                                    ),
                                    e => error!(
                                        log,
                                        "Error applying attestation to fork choice";
                                        "reason" => format!("{:?}", e),
                                        "peer" => peer_id.to_string(),
                                        "beacon_block_root" => format!("{:?}", beacon_block_root)
                                    ),
                                }
                            }

                            if let Err(e) = chain.add_to_naive_aggregation_pool(attestation) {
                                debug!(
                                    log,
                                    "Attestation invalid for agg pool";
                                    "reason" => format!("{:?}", e),
                                    "peer" => peer_id.to_string(),
                                    "beacon_block_root" => format!("{:?}", beacon_block_root)
                                )
                            }

                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_IMPORTED_TOTAL,
                            );
                        }
                        /*
                         * Aggregated attestation verification.
                         */
                        Work::GossipAggregate {
                            message_id,
                            peer_id,
                            aggregate,
                        } => {
                            let beacon_block_root =
                                aggregate.message.aggregate.data.beacon_block_root;

                            let aggregate =
                                match chain.verify_aggregated_attestation_for_gossip(*aggregate) {
                                    Ok(aggregate) => aggregate,
                                    Err(e) => {
                                        handle_attestation_verification_failure(
                                            &log,
                                            sync_tx,
                                            peer_id,
                                            beacon_block_root,
                                            "aggregated",
                                            e,
                                        );
                                        return;
                                    }
                                };

                            // Indicate to the `Network` service that this message is valid and can be
                            // propagated on the gossip network.
                            propagate_gossip_message(network_tx, message_id, peer_id.clone(), &log);

                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_VERIFIED_TOTAL,
                            );

                            if let Err(e) = chain.apply_attestation_to_fork_choice(&aggregate) {
                                match e {
                                    BeaconChainError::ForkChoiceError(
                                        ForkChoiceError::InvalidAttestation(e),
                                    ) => debug!(
                                        log,
                                        "Aggregate invalid for fork choice";
                                        "reason" => format!("{:?}", e),
                                        "peer" => peer_id.to_string(),
                                        "beacon_block_root" => format!("{:?}", beacon_block_root)
                                    ),
                                    e => error!(
                                        log,
                                        "Error applying aggregate to fork choice";
                                        "reason" => format!("{:?}", e),
                                        "peer" => peer_id.to_string(),
                                        "beacon_block_root" => format!("{:?}", beacon_block_root)
                                    ),
                                }
                            }

                            if let Err(e) = chain.add_to_block_inclusion_pool(aggregate) {
                                debug!(
                                    log,
                                    "Attestation invalid for op pool";
                                    "reason" => format!("{:?}", e),
                                    "peer" => peer_id.to_string(),
                                    "beacon_block_root" => format!("{:?}", beacon_block_root)
                                )
                            }

                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_IMPORTED_TOTAL,
                            );
                        }
                        /*
                         * Verification for beacon blocks received on gossip.
                         */
                        Work::GossipBlock {
                            message_id,
                            peer_id,
                            block,
                        } => {
                            let verified_block = match chain.verify_block_for_gossip(*block) {
                                Ok(verified_block) => {
                                    info!(
                                        log,
                                        "New block received";
                                        "slot" => verified_block.block.slot(),
                                        "hash" => verified_block.block_root.to_string()
                                    );
                                    propagate_gossip_message(
                                        network_tx,
                                        message_id,
                                        peer_id.clone(),
                                        &log,
                                    );
                                    verified_block
                                }
                                Err(BlockError::ParentUnknown(block)) => {
                                    send_sync_message(
                                        sync_tx,
                                        SyncMessage::UnknownBlock(peer_id, block),
                                        &log,
                                    );
                                    return;
                                }
                                Err(BlockError::BlockIsAlreadyKnown) => {
                                    debug!(
                                        log,
                                        "Gossip block is already known";
                                    );
                                    return;
                                }
                                Err(e) => {
                                    warn!(
                                        log,
                                        "Could not verify block for gossip";
                                        "error" => format!("{:?}", e)
                                    );
                                    return;
                                }
                            };

                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_VERIFIED_TOTAL,
                            );

                            let block = Box::new(verified_block.block.clone());
                            match chain.process_block(verified_block) {
                                Ok(_block_root) => {
                                    metrics::inc_counter(
                                        &metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_IMPORTED_TOTAL,
                                    );

                                    trace!(
                                        log,
                                        "Gossipsub block processed";
                                        "peer_id" => peer_id.to_string()
                                    );

                                    // TODO: It would be better if we can run this _after_ we publish the block to
                                    // reduce block propagation latency.
                                    //
                                    // The `MessageHandler` would be the place to put this, however it doesn't seem
                                    // to have a reference to the `BeaconChain`. I will leave this for future
                                    // works.
                                    match chain.fork_choice() {
                                        Ok(()) => trace!(
                                            log,
                                            "Fork choice success";
                                            "location" => "block gossip"
                                        ),
                                        Err(e) => error!(
                                            log,
                                            "Fork choice failed";
                                            "error" => format!("{:?}", e),
                                            "location" => "block gossip"
                                        ),
                                    }
                                }
                                Err(BlockError::ParentUnknown { .. }) => {
                                    // Inform the sync manager to find parents for this block
                                    // This should not occur. It should be checked by `should_forward_block`
                                    error!(
                                        log,
                                        "Block with unknown parent attempted to be processed";
                                        "peer_id" => peer_id.to_string()
                                    );
                                    send_sync_message(
                                        sync_tx,
                                        SyncMessage::UnknownBlock(peer_id, block),
                                        &log,
                                    );
                                }
                                other => {
                                    debug!(
                                        log,
                                        "Invalid gossip beacon block";
                                        "outcome" => format!("{:?}", other),
                                        "block root" => format!("{}", block.canonical_root()),
                                        "block slot" => block.slot()
                                    );
                                    trace!(
                                        log,
                                        "Invalid gossip beacon block ssz";
                                        "ssz" => format!("0x{}", hex::encode(block.as_ssz_bytes())),
                                    );
                                }
                            };
                        }
                        /*
                         * Verification for beacon blocks received during syncing via RPC.
                         */
                        Work::RpcBlock { block, result_tx } => {
                            let block_result = chain.process_block(*block);

                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_RPC_BLOCK_IMPORTED_TOTAL,
                            );

                            if result_tx.send(block_result).is_err() {
                                crit!(log, "Failed return sync block result");
                            }
                        }
                        /*
                         * Verification for a chain segment (multiple blocks).
                         */
                        Work::ChainSegment { process_id, blocks } => {
                            handle_chain_segment(chain, process_id, blocks, sync_tx, log)
                        }
                    };
                };
                handler();

                trace!(
                    log,
                    "Beacon processor worker done";
                    "work" => work_id,
                    "worker" => worker_id,
                );

                idle_tx.try_send(()).unwrap_or_else(|e| {
                    crit!(
                        log,
                        "Unable to free worker";
                        "msg" => "failed to send idle_tx message",
                        "error" => e.to_string()
                    )
                });
            },
            WORKER_TASK_NAME,
        );
    }
}

/// Send a message on `message_tx` that the `message_id` sent by `peer_id` should be propagated on
/// the gossip network.
///
/// Creates a log if there is an interal error.
fn propagate_gossip_message<E: EthSpec>(
    network_tx: mpsc::UnboundedSender<NetworkMessage<E>>,
    message_id: MessageId,
    peer_id: PeerId,
    log: &Logger,
) {
    network_tx
        .send(NetworkMessage::Validate {
            propagation_source: peer_id,
            message_id,
        })
        .unwrap_or_else(|_| {
            warn!(
                log,
                "Could not send propagation request to the network service"
            )
        });
}

/// Send a message to `sync_tx`.
///
/// Creates a log if there is an interal error.
fn send_sync_message<E: EthSpec>(
    sync_tx: mpsc::UnboundedSender<SyncMessage<E>>,
    message: SyncMessage<E>,
    log: &Logger,
) {
    sync_tx
        .send(message)
        .unwrap_or_else(|_| error!(log, "Could not send message to the sync service"));
}

/// Handle an error whilst verifying an `Attestation` or `SignedAggregateAndProof` from the
/// network.
pub fn handle_attestation_verification_failure<E: EthSpec>(
    log: &Logger,
    sync_tx: mpsc::UnboundedSender<SyncMessage<E>>,
    peer_id: PeerId,
    beacon_block_root: Hash256,
    attestation_type: &str,
    error: AttnError,
) {
    metrics::register_attestation_error(&error);
    match &error {
        AttnError::FutureEpoch { .. }
        | AttnError::PastEpoch { .. }
        | AttnError::FutureSlot { .. }
        | AttnError::PastSlot { .. } => {
            /*
             * These errors can be triggered by a mismatch between our slot and the peer.
             *
             *
             * The peer has published an invalid consensus message, _only_ if we trust our own clock.
             */
        }
        AttnError::InvalidSelectionProof { .. } | AttnError::InvalidSignature => {
            /*
             * These errors are caused by invalid signatures.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::EmptyAggregationBitfield => {
            /*
             * The aggregate had no signatures and is therefore worthless.
             *
             * Whilst we don't gossip this attestation, this act is **not** a clear
             * violation of the spec nor indication of fault.
             *
             * This may change soon. Reference:
             *
             * https://github.com/ethereum/eth2.0-specs/pull/1732
             */
        }
        AttnError::AggregatorPubkeyUnknown(_) => {
            /*
             * The aggregator index was higher than any known validator index. This is
             * possible in two cases:
             *
             * 1. The attestation is malformed
             * 2. The attestation attests to a beacon_block_root that we do not know.
             *
             * It should be impossible to reach (2) without triggering
             * `AttnError::UnknownHeadBlock`, so we can safely assume the peer is
             * faulty.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::AggregatorNotInCommittee { .. } => {
            /*
             * The aggregator index was higher than any known validator index. This is
             * possible in two cases:
             *
             * 1. The attestation is malformed
             * 2. The attestation attests to a beacon_block_root that we do not know.
             *
             * It should be impossible to reach (2) without triggering
             * `AttnError::UnknownHeadBlock`, so we can safely assume the peer is
             * faulty.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::AttestationAlreadyKnown { .. } => {
            /*
             * The aggregate attestation has already been observed on the network or in
             * a block.
             *
             * The peer is not necessarily faulty.
             */
            trace!(
                log,
                "Attestation already known";
                "peer_id" => peer_id.to_string(),
                "block" => format!("{}", beacon_block_root),
                "type" => format!("{:?}", attestation_type),
            );
            return;
        }
        AttnError::AggregatorAlreadyKnown(_) => {
            /*
             * There has already been an aggregate attestation seen from this
             * aggregator index.
             *
             * The peer is not necessarily faulty.
             */
            trace!(
                log,
                "Aggregator already known";
                "peer_id" => peer_id.to_string(),
                "block" => format!("{}", beacon_block_root),
                "type" => format!("{:?}", attestation_type),
            );
            return;
        }
        AttnError::PriorAttestationKnown { .. } => {
            /*
             * We have already seen an attestation from this validator for this epoch.
             *
             * The peer is not necessarily faulty.
             */
            trace!(
                log,
                "Prior attestation known";
                "peer_id" => peer_id.to_string(),
                "block" => format!("{}", beacon_block_root),
                "type" => format!("{:?}", attestation_type),
            );
            return;
        }
        AttnError::ValidatorIndexTooHigh(_) => {
            /*
             * The aggregator index (or similar field) was higher than the maximum
             * possible number of validators.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::UnknownHeadBlock { beacon_block_root } => {
            // Note: its a little bit unclear as to whether or not this block is unknown or
            // just old. See:
            //
            // https://github.com/sigp/lighthouse/issues/1039

            // TODO: Maintain this attestation and re-process once sync completes
            debug!(
                log,
                "Attestation for unknown block";
                "peer_id" => peer_id.to_string(),
                "block" => format!("{}", beacon_block_root)
            );
            // we don't know the block, get the sync manager to handle the block lookup
            sync_tx
                .send(SyncMessage::UnknownBlockHash(peer_id, *beacon_block_root))
                .unwrap_or_else(|_| {
                    warn!(
                        log,
                        "Failed to send to sync service";
                        "msg" => "UnknownBlockHash"
                    )
                });
            return;
        }
        AttnError::UnknownTargetRoot(_) => {
            /*
             * The block indicated by the target root is not known to us.
             *
             * We should always get `AttnError::UnknwonHeadBlock` before we get this
             * error, so this means we can get this error if:
             *
             * 1. The target root does not represent a valid block.
             * 2. We do not have the target root in our DB.
             *
             * For (2), we should only be processing attestations when we should have
             * all the available information. Note: if we do a weak-subjectivity sync
             * it's possible that this situation could occur, but I think it's
             * unlikely. For now, we will declare this to be an invalid message>
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::BadTargetEpoch => {
            /*
             * The aggregator index (or similar field) was higher than the maximum
             * possible number of validators.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::NoCommitteeForSlotAndIndex { .. } => {
            /*
             * It is not possible to attest this the given committee in the given slot.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::NotExactlyOneAggregationBitSet(_) => {
            /*
             * The unaggregated attestation doesn't have only one signature.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::AttestsToFutureBlock { .. } => {
            /*
             * The beacon_block_root is from a higher slot than the attestation.
             *
             * The peer has published an invalid consensus message.
             */
        }

        AttnError::InvalidSubnetId { received, expected } => {
            /*
             * The attestation was received on an incorrect subnet id.
             */
            debug!(
                log,
                "Received attestation on incorrect subnet";
                "expected" => format!("{:?}", expected),
                "received" => format!("{:?}", received),
            )
        }
        AttnError::Invalid(_) => {
            /*
             * The attestation failed the state_processing verification.
             *
             * The peer has published an invalid consensus message.
             */
        }
        AttnError::TooManySkippedSlots {
            head_block_slot,
            attestation_slot,
        } => {
            /*
             * The attestation references a head block that is too far behind the attestation slot.
             *
             * The message is not necessarily invalid, but we choose to ignore it.
             */
            debug!(
                log,
                "Rejected long skip slot attestation";
                "head_block_slot" => head_block_slot,
                "attestation_slot" => attestation_slot,
            )
        }
        AttnError::BeaconChainError(e) => {
            /*
             * Lighthouse hit an unexpected error whilst processing the attestation. It
             * should be impossible to trigger a `BeaconChainError` from the network,
             * so we have a bug.
             *
             * It's not clear if the message is invalid/malicious.
             */
            error!(
                log,
                "Unable to validate aggregate";
                "peer_id" => peer_id.to_string(),
                "error" => format!("{:?}", e),
            );
        }
    }

    debug!(
        log,
        "Invalid attestation from network";
        "reason" => format!("{:?}", error),
        "block" => format!("{}", beacon_block_root),
        "peer_id" => peer_id.to_string(),
        "type" => format!("{:?}", attestation_type),
    );
}
