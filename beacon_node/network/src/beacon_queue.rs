use crate::{metrics, service::NetworkMessage, sync::SyncMessage};
use beacon_chain::{
    attestation_verification::Error as AttnError, BeaconChain, BeaconChainError, BeaconChainTypes,
    ForkChoiceError,
};
use environment::TaskExecutor;
use eth2_libp2p::{MessageId, PeerId};
use slog::{crit, debug, error, trace, warn, Logger};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{Attestation, EthSpec, Hash256, SubnetId};

const MAX_WORK_QUEUE_LEN: usize = 65_535;
const MAX_UNAGGREGATED_ATTESTATION_QUEUE_LEN: usize = 1_024;
const MANAGER_TASK_NAME: &str = "beacon_gossip_processor_manager";
const WORKER_TASK_NAME: &str = "beacon_gossip_processor_worker";

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

    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.max_length
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
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
    pub fn unaggregated_attestation(
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Attestation<E>,
        subnet_id: SubnetId,
        should_import: bool,
    ) -> Self {
        Event::Work {
            message_id,
            peer_id,
            work: Work::Attestation((attestation, subnet_id, should_import)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Work<E: EthSpec> {
    Attestation((Attestation<E>, SubnetId, bool)),
}

pub struct BeaconGossipProcessor<T: BeaconChainTypes> {
    pub beacon_chain: Arc<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub executor: TaskExecutor,
    pub max_workers: usize,
    pub current_workers: usize,
    pub log: Logger,
}

impl<T: BeaconChainTypes> BeaconGossipProcessor<T> {
    pub fn spawn_manager(mut self) -> mpsc::Sender<Event<T::EthSpec>> {
        let (event_tx, mut event_rx) = mpsc::channel::<Event<T::EthSpec>>(MAX_WORK_QUEUE_LEN);
        let mut attestation_queue = Queue::new(MAX_UNAGGREGATED_ATTESTATION_QUEUE_LEN);
        let inner_event_tx = event_tx.clone();

        self.executor.clone().spawn(
            async move {
                while let Some(event) = event_rx.recv().await {
                    let _event_timer =
                        metrics::start_timer(&metrics::GOSSIP_PROCESSOR_EVENT_HANDLING_SECONDS);

                    if event == Event::WorkerIdle {
                        self.current_workers = self.current_workers.saturating_sub(1);
                    }

                    let can_spawn = self.current_workers < self.max_workers;

                    match event {
                        Event::WorkerIdle => {
                            if let Some(item) = attestation_queue.pop() {
                                self.spawn_worker(
                                    inner_event_tx.clone(),
                                    item.message_id,
                                    item.peer_id,
                                    Work::Attestation(item.item),
                                );
                            }
                        }
                        Event::Work {
                            message_id,
                            peer_id,
                            work,
                        } => match work {
                            Work::Attestation(_) if can_spawn => {
                                self.spawn_worker(inner_event_tx.clone(), message_id, peer_id, work)
                            }
                            Work::Attestation(attestation) => attestation_queue.push(QueueItem {
                                message_id,
                                peer_id,
                                item: attestation,
                            }),
                        },
                    }

                    metrics::set_gauge(
                        &metrics::GOSSIP_PROCESSOR_WORKERS_ACTIVE_TOTAL,
                        self.current_workers as i64,
                    );
                    metrics::set_gauge(
                        &metrics::GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_QUEUE_TOTAL,
                        attestation_queue.len() as i64,
                    );

                    // TODO: rate limit the logs below.

                    if attestation_queue.is_full() {
                        error!(
                            self.log,
                            "Attestation queue full";
                            "msg" => "the system has insufficient resources for load",
                            "queue_len" => attestation_queue.max_length,
                        )
                    }
                }
            },
            MANAGER_TASK_NAME,
        );

        event_tx
    }

    fn spawn_worker(
        &mut self,
        mut event_tx: mpsc::Sender<Event<T::EthSpec>>,
        message_id: MessageId,
        peer_id: PeerId,
        work: Work<T::EthSpec>,
    ) {
        let worker_timer = metrics::start_timer(&metrics::GOSSIP_PROCESSOR_WORKER_TIME);
        metrics::inc_counter(&metrics::GOSSIP_PROCESSOR_WORKERS_SPAWNED_TOTAL);

        self.current_workers = self.current_workers.saturating_add(1);
        let chain = self.beacon_chain.clone();
        let network_tx = self.network_tx.clone();
        let sync_tx = self.sync_tx.clone();
        let log = self.log.clone();

        self.executor.spawn_blocking(
            move || {
                let _worker_timer = worker_timer;

                // We use this closure pattern to avoid using a `return` that prevents the
                // `WorkerIdle` message from sending.
                let handler = || {
                    match work {
                        Work::Attestation((attestation, subnet_id, should_import)) => {
                            let _attestation_timer = metrics::start_timer(
                                &metrics::GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_WORKER_TIME,
                            );
                            metrics::inc_counter(
                                &metrics::GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_VERIFIED_TOTAL,
                            );

                            let beacon_block_root = attestation.data.beacon_block_root;

                            let attestation = if let Ok(attestation) = chain
                                .verify_unaggregated_attestation_for_gossip(attestation, subnet_id)
                                .map_err(|e| {
                                    handle_attestation_verification_failure(
                                        &log,
                                        sync_tx,
                                        peer_id.clone(),
                                        beacon_block_root,
                                        "unaggregated",
                                        e,
                                    )
                                }) {
                                attestation
                            } else {
                                return;
                            };

                            // Indicate to the `Network` service that this message is valid and can be
                            // propagated on the gossip network.
                            propagate_gossip_message(network_tx, message_id, peer_id.clone(), &log);

                            if !should_import {
                                return;
                            }

                            metrics::inc_counter(
                                &metrics::GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_IMPORTED_TOTAL,
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
                        }
                    };
                };
                handler();

                event_tx.try_send(Event::WorkerIdle).unwrap_or_else(|e| {
                    crit!(
                        log,
                        "Unable to free worker";
                        "msg" => "failed to send WorkerIdle message",
                        "error" => e.to_string()
                    )
                });
            },
            WORKER_TASK_NAME,
        );
    }
}

fn propagate_gossip_message<E: EthSpec>(
    network_tx: mpsc::UnboundedSender<NetworkMessage<E>>,
    message_id: MessageId,
    propagation_source: PeerId,
    log: &Logger,
) {
    network_tx
        .send(NetworkMessage::Validate {
            propagation_source,
            message_id,
        })
        .unwrap_or_else(|_| {
            warn!(
                log,
                "Could not send propagation request to the network service"
            )
        });
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
