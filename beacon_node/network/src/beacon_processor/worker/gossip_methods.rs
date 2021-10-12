use crate::{metrics, service::NetworkMessage, sync::SyncMessage};

use beacon_chain::{
    attestation_verification::{Error as AttnError, VerifiedAttestation},
    observed_operations::ObservationOutcome,
    sync_committee_verification::Error as SyncCommitteeError,
    validator_monitor::get_block_delay_ms,
    BeaconChainError, BeaconChainTypes, BlockError, ForkChoiceError, GossipVerifiedBlock,
};
use eth2_libp2p::{Client, MessageAcceptance, MessageId, PeerAction, PeerId, ReportSource};
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use ssz::Encode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use types::{
    Attestation, AttesterSlashing, EthSpec, Hash256, IndexedAttestation, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedContributionAndProof, SignedVoluntaryExit,
    SubnetId, SyncCommitteeMessage, SyncSubnetId,
};

use super::{
    super::work_reprocessing_queue::{
        QueuedAggregate, QueuedBlock, QueuedUnaggregate, ReprocessQueueMessage,
    },
    Worker,
};

/// An attestation that has been validated by the `BeaconChain`.
///
/// Since this struct implements `beacon_chain::VerifiedAttestation`, it would be a logic error to
/// construct this from components which have not passed `BeaconChain` validation.
struct VerifiedUnaggregate<T: BeaconChainTypes> {
    attestation: Box<Attestation<T::EthSpec>>,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
}

/// This implementation allows `Self` to be imported to fork choice and other functions on the
/// `BeaconChain`.
impl<'a, T: BeaconChainTypes> VerifiedAttestation<T> for VerifiedUnaggregate<T> {
    fn attestation(&self) -> &Attestation<T::EthSpec> {
        &self.attestation
    }

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }
}

/// An attestation that failed validation by the `BeaconChain`.
struct RejectedUnaggregate<T: EthSpec> {
    attestation: Box<Attestation<T>>,
    error: AttnError,
}

/// An aggregate that has been validated by the `BeaconChain`.
///
/// Since this struct implements `beacon_chain::VerifiedAttestation`, it would be a logic error to
/// construct this from components which have not passed `BeaconChain` validation.
struct VerifiedAggregate<T: BeaconChainTypes> {
    signed_aggregate: Box<SignedAggregateAndProof<T::EthSpec>>,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
}

/// This implementation allows `Self` to be imported to fork choice and other functions on the
/// `BeaconChain`.
impl<'a, T: BeaconChainTypes> VerifiedAttestation<T> for VerifiedAggregate<T> {
    fn attestation(&self) -> &Attestation<T::EthSpec> {
        &self.signed_aggregate.message.aggregate
    }

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }
}

/// An attestation that failed validation by the `BeaconChain`.
struct RejectedAggregate<T: EthSpec> {
    signed_aggregate: Box<SignedAggregateAndProof<T>>,
    error: AttnError,
}

/// Data for an aggregated or unaggregated attestation that failed verification.
enum FailedAtt<T: EthSpec> {
    Unaggregate {
        attestation: Box<Attestation<T>>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    },
    Aggregate {
        attestation: Box<SignedAggregateAndProof<T>>,
        seen_timestamp: Duration,
    },
}

impl<T: EthSpec> FailedAtt<T> {
    pub fn beacon_block_root(&self) -> &Hash256 {
        match self {
            FailedAtt::Unaggregate { attestation, .. } => &attestation.data.beacon_block_root,
            FailedAtt::Aggregate { attestation, .. } => {
                &attestation.message.aggregate.data.beacon_block_root
            }
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            FailedAtt::Unaggregate { .. } => "unaggregated",
            FailedAtt::Aggregate { .. } => "aggregated",
        }
    }
}

/// Items required to verify a batch of unaggregated gossip attestations.
#[derive(Debug)]
pub struct GossipAttestationPackage<E: EthSpec> {
    message_id: MessageId,
    peer_id: PeerId,
    attestation: Box<Attestation<E>>,
    subnet_id: SubnetId,
    beacon_block_root: Hash256,
    should_import: bool,
    seen_timestamp: Duration,
}

impl<E: EthSpec> GossipAttestationPackage<E> {
    pub fn new(
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Box<Attestation<E>>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    ) -> Self {
        Self {
            message_id,
            peer_id,
            beacon_block_root: attestation.data.beacon_block_root,
            attestation,
            subnet_id,
            should_import,
            seen_timestamp,
        }
    }
}

/// Items required to verify a batch of aggregated gossip attestations.
#[derive(Debug)]
pub struct GossipAggregatePackage<E: EthSpec> {
    message_id: MessageId,
    peer_id: PeerId,
    aggregate: Box<SignedAggregateAndProof<E>>,
    beacon_block_root: Hash256,
    seen_timestamp: Duration,
}

impl<E: EthSpec> GossipAggregatePackage<E> {
    pub fn new(
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: Box<SignedAggregateAndProof<E>>,
        seen_timestamp: Duration,
    ) -> Self {
        Self {
            message_id,
            peer_id,
            beacon_block_root: aggregate.message.aggregate.data.beacon_block_root,
            aggregate,
            seen_timestamp,
        }
    }
}

impl<T: BeaconChainTypes> Worker<T> {
    /* Auxiliary functions */

    /// Penalizes a peer for misbehaviour.
    fn gossip_penalize_peer(&self, peer_id: PeerId, action: PeerAction) {
        self.send_network_message(NetworkMessage::ReportPeer {
            peer_id,
            action,
            source: ReportSource::Gossipsub,
        })
    }

    /// Send a message on `message_tx` that the `message_id` sent by `peer_id` should be propagated on
    /// the gossip network.
    ///
    /// Creates a log if there is an internal error.
    /// Propagates the result of the validation for the given message to the network. If the result
    /// is valid the message gets forwarded to other peers.
    fn propagate_validation_result(
        &self,
        message_id: MessageId,
        propagation_source: PeerId,
        validation_result: MessageAcceptance,
    ) {
        self.send_network_message(NetworkMessage::ValidationResult {
            propagation_source,
            message_id,
            validation_result,
        })
    }

    /* Processing functions */

    /// Process the unaggregated attestation received from the gossip network and:
    ///
    /// - If it passes gossip propagation criteria, tell the network thread to forward it.
    /// - Attempt to apply it to fork choice.
    /// - Attempt to add it to the naive aggregation pool.
    ///
    /// Raises a log if there are errors.
    #[allow(clippy::too_many_arguments)]
    pub fn process_gossip_attestation(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Box<Attestation<T::EthSpec>>,
        subnet_id: SubnetId,
        should_import: bool,
        reprocess_tx: Option<mpsc::Sender<ReprocessQueueMessage<T>>>,
        seen_timestamp: Duration,
    ) {
        let result = match self
            .chain
            .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id))
        {
            Ok(verified_attestation) => Ok(VerifiedUnaggregate {
                indexed_attestation: verified_attestation.into_indexed_attestation(),
                attestation,
            }),
            Err(error) => Err(RejectedUnaggregate { attestation, error }),
        };

        self.process_gossip_attestation_result(
            result,
            message_id,
            peer_id,
            subnet_id,
            reprocess_tx,
            should_import,
            seen_timestamp,
        );
    }

    pub fn process_gossip_attestation_batch(
        self,
        packages: Vec<GossipAttestationPackage<T::EthSpec>>,
        reprocess_tx: Option<mpsc::Sender<ReprocessQueueMessage<T>>>,
    ) {
        let attestations_and_subnets = packages
            .iter()
            .map(|package| (package.attestation.as_ref(), Some(package.subnet_id)));

        let results = match self
            .chain
            .batch_verify_unaggregated_attestations_for_gossip(attestations_and_subnets)
        {
            Ok(results) => results,
            Err(e) => {
                error!(
                    self.log,
                    "Batch unagg. attn verification failed";
                    "error" => ?e
                );
                return;
            }
        };

        // Sanity check.
        if results.len() != packages.len() {
            // The log is `crit` since in this scenario we might be penalizing/rewarding the wrong
            // peer.
            crit!(
                self.log,
                "Batch attestation result mismatch";
                "results" => results.len(),
                "packages" => packages.len(),
            )
        }

        // Map the results into a new `Vec` so that `results` no longer holds a reference to
        // `packages`.
        #[allow(clippy::needless_collect)] // The clippy suggestion fails the borrow checker.
        let results = results
            .into_iter()
            .map(|result| result.map(|verified| verified.into_indexed_attestation()))
            .collect::<Vec<_>>();

        for (result, package) in results.into_iter().zip(packages.into_iter()) {
            let result = match result {
                Ok(indexed_attestation) => Ok(VerifiedUnaggregate {
                    indexed_attestation,
                    attestation: package.attestation,
                }),
                Err(error) => Err(RejectedUnaggregate {
                    attestation: package.attestation,
                    error,
                }),
            };

            self.process_gossip_attestation_result(
                result,
                package.message_id,
                package.peer_id,
                package.subnet_id,
                reprocess_tx.clone(),
                package.should_import,
                package.seen_timestamp,
            );
        }
    }

    // Clippy warning is is ignored since the arguments are all of a different type (i.e., they
    // cant' be mixed-up) and creating a struct would result in more complexity.
    #[allow(clippy::too_many_arguments)]
    fn process_gossip_attestation_result(
        &self,
        result: Result<VerifiedUnaggregate<T>, RejectedUnaggregate<T::EthSpec>>,
        message_id: MessageId,
        peer_id: PeerId,
        subnet_id: SubnetId,
        reprocess_tx: Option<mpsc::Sender<ReprocessQueueMessage<T>>>,
        should_import: bool,
        seen_timestamp: Duration,
    ) {
        match result {
            Ok(verified_attestation) => {
                let indexed_attestation = &verified_attestation.indexed_attestation;
                let beacon_block_root = indexed_attestation.data.beacon_block_root;

                // Register the attestation with any monitored validators.
                self.chain
                    .validator_monitor
                    .read()
                    .register_gossip_unaggregated_attestation(
                        seen_timestamp,
                        indexed_attestation,
                        &self.chain.slot_clock,
                    );

                // Indicate to the `Network` service that this message is valid and can be
                // propagated on the gossip network.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

                if !should_import {
                    return;
                }

                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_VERIFIED_TOTAL,
                );

                if let Err(e) = self
                    .chain
                    .apply_attestation_to_fork_choice(&verified_attestation)
                {
                    match e {
                        BeaconChainError::ForkChoiceError(ForkChoiceError::InvalidAttestation(
                            e,
                        )) => {
                            debug!(
                                self.log,
                                "Attestation invalid for fork choice";
                                "reason" => ?e,
                                "peer" => %peer_id,
                                "beacon_block_root" => ?beacon_block_root
                            )
                        }
                        e => error!(
                            self.log,
                            "Error applying attestation to fork choice";
                            "reason" => ?e,
                            "peer" => %peer_id,
                            "beacon_block_root" => ?beacon_block_root
                        ),
                    }
                }

                if let Err(e) = self
                    .chain
                    .add_to_naive_aggregation_pool(&verified_attestation)
                {
                    debug!(
                        self.log,
                        "Attestation invalid for agg pool";
                        "reason" => ?e,
                        "peer" => %peer_id,
                        "beacon_block_root" => ?beacon_block_root
                    )
                }

                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_IMPORTED_TOTAL,
                );
            }
            Err(RejectedUnaggregate { attestation, error }) => {
                self.handle_attestation_verification_failure(
                    peer_id,
                    message_id,
                    FailedAtt::Unaggregate {
                        attestation,
                        subnet_id,
                        should_import,
                        seen_timestamp,
                    },
                    reprocess_tx,
                    error,
                );
            }
        }
    }

    /// Process the aggregated attestation received from the gossip network and:
    ///
    /// - If it passes gossip propagation criteria, tell the network thread to forward it.
    /// - Attempt to apply it to fork choice.
    /// - Attempt to add it to the block inclusion pool.
    ///
    /// Raises a log if there are errors.
    pub fn process_gossip_aggregate(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: Box<SignedAggregateAndProof<T::EthSpec>>,
        reprocess_tx: Option<mpsc::Sender<ReprocessQueueMessage<T>>>,
        seen_timestamp: Duration,
    ) {
        let beacon_block_root = aggregate.message.aggregate.data.beacon_block_root;

        let result = match self
            .chain
            .verify_aggregated_attestation_for_gossip(&aggregate)
        {
            Ok(verified_aggregate) => Ok(VerifiedAggregate {
                indexed_attestation: verified_aggregate.into_indexed_attestation(),
                signed_aggregate: aggregate,
            }),
            Err(error) => Err(RejectedAggregate {
                signed_aggregate: aggregate,
                error,
            }),
        };

        self.process_gossip_aggregate_result(
            result,
            beacon_block_root,
            message_id,
            peer_id,
            reprocess_tx,
            seen_timestamp,
        );
    }

    pub fn process_gossip_aggregate_batch(
        self,
        packages: Vec<GossipAggregatePackage<T::EthSpec>>,
        reprocess_tx: Option<mpsc::Sender<ReprocessQueueMessage<T>>>,
    ) {
        let aggregates = packages.iter().map(|package| package.aggregate.as_ref());

        let results = match self
            .chain
            .batch_verify_aggregated_attestations_for_gossip(aggregates)
        {
            Ok(results) => results,
            Err(e) => {
                error!(
                    self.log,
                    "Batch agg. attn verification failed";
                    "error" => ?e
                );
                return;
            }
        };

        // Sanity check.
        if results.len() != packages.len() {
            // The log is `crit` since in this scenario we might be penalizing/rewarding the wrong
            // peer.
            crit!(
                self.log,
                "Batch agg. attestation result mismatch";
                "results" => results.len(),
                "packages" => packages.len(),
            )
        }

        // Map the results into a new `Vec` so that `results` no longer holds a reference to
        // `packages`.
        #[allow(clippy::needless_collect)] // The clippy suggestion fails the borrow checker.
        let results = results
            .into_iter()
            .map(|result| result.map(|verified| verified.into_indexed_attestation()))
            .collect::<Vec<_>>();

        for (result, package) in results.into_iter().zip(packages.into_iter()) {
            let result = match result {
                Ok(indexed_attestation) => Ok(VerifiedAggregate {
                    indexed_attestation,
                    signed_aggregate: package.aggregate,
                }),
                Err(error) => Err(RejectedAggregate {
                    signed_aggregate: package.aggregate,
                    error,
                }),
            };

            self.process_gossip_aggregate_result(
                result,
                package.beacon_block_root,
                package.message_id,
                package.peer_id,
                reprocess_tx.clone(),
                package.seen_timestamp,
            );
        }
    }

    fn process_gossip_aggregate_result(
        &self,
        result: Result<VerifiedAggregate<T>, RejectedAggregate<T::EthSpec>>,
        beacon_block_root: Hash256,
        message_id: MessageId,
        peer_id: PeerId,
        reprocess_tx: Option<mpsc::Sender<ReprocessQueueMessage<T>>>,
        seen_timestamp: Duration,
    ) {
        match result {
            Ok(verified_aggregate) => {
                let aggregate = &verified_aggregate.signed_aggregate;
                let indexed_attestation = &verified_aggregate.indexed_attestation;

                // Indicate to the `Network` service that this message is valid and can be
                // propagated on the gossip network.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

                // Register the attestation with any monitored validators.
                self.chain
                    .validator_monitor
                    .read()
                    .register_gossip_aggregated_attestation(
                        seen_timestamp,
                        aggregate,
                        indexed_attestation,
                        &self.chain.slot_clock,
                    );

                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_VERIFIED_TOTAL,
                );

                if let Err(e) = self
                    .chain
                    .apply_attestation_to_fork_choice(&verified_aggregate)
                {
                    match e {
                        BeaconChainError::ForkChoiceError(ForkChoiceError::InvalidAttestation(
                            e,
                        )) => {
                            debug!(
                                self.log,
                                "Aggregate invalid for fork choice";
                                "reason" => ?e,
                                "peer" => %peer_id,
                                "beacon_block_root" => ?beacon_block_root
                            )
                        }
                        e => error!(
                            self.log,
                            "Error applying aggregate to fork choice";
                            "reason" => ?e,
                            "peer" => %peer_id,
                            "beacon_block_root" => ?beacon_block_root
                        ),
                    }
                }

                if let Err(e) = self.chain.add_to_block_inclusion_pool(&verified_aggregate) {
                    debug!(
                        self.log,
                        "Attestation invalid for op pool";
                        "reason" => ?e,
                        "peer" => %peer_id,
                        "beacon_block_root" => ?beacon_block_root
                    )
                }

                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_IMPORTED_TOTAL,
                );
            }
            Err(RejectedAggregate {
                signed_aggregate,
                error,
            }) => {
                // Report the failure to gossipsub
                self.handle_attestation_verification_failure(
                    peer_id,
                    message_id,
                    FailedAtt::Aggregate {
                        attestation: signed_aggregate,
                        seen_timestamp,
                    },
                    reprocess_tx,
                    error,
                );
            }
        }
    }

    /// Process the beacon block received from the gossip network and:
    ///
    /// - If it passes gossip propagation criteria, tell the network thread to forward it.
    /// - Attempt to add it to the beacon chain, informing the sync thread if more blocks need to
    ///   be downloaded.
    ///
    /// Raises a log if there are errors.
    pub fn process_gossip_block(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: SignedBeaconBlock<T::EthSpec>,
        reprocess_tx: mpsc::Sender<ReprocessQueueMessage<T>>,
        seen_duration: Duration,
    ) {
        let block_delay =
            get_block_delay_ms(seen_duration, block.message(), &self.chain.slot_clock);
        // Log metrics to track delay from other nodes on the network.
        metrics::observe_duration(
            &metrics::BEACON_BLOCK_GOSSIP_SLOT_START_DELAY_TIME,
            block_delay,
        );

        // Write the time the block was observed into delay cache.
        self.chain.block_times_cache.write().set_time_observed(
            block.canonical_root(),
            block.slot(),
            seen_duration,
            Some(peer_id.to_string()),
            Some(peer_client.to_string()),
        );

        let verified_block = match self.chain.verify_block_for_gossip(block) {
            Ok(verified_block) => {
                if block_delay >= self.chain.slot_clock.unagg_attestation_production_delay() {
                    metrics::inc_counter(&metrics::BEACON_BLOCK_GOSSIP_ARRIVED_LATE_TOTAL);
                    debug!(
                        self.log,
                        "Gossip block arrived late";
                        "block_root" => ?verified_block.block_root,
                        "proposer_index" => verified_block.block.message().proposer_index(),
                        "slot" => verified_block.block.slot(),
                        "block_delay" => ?block_delay,
                    );
                }

                info!(
                    self.log,
                    "New block received";
                    "slot" => verified_block.block.slot(),
                    "hash" => ?verified_block.block_root
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

                // Log metrics to keep track of propagation delay times.
                if let Some(duration) = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|now| now.checked_sub(seen_duration))
                {
                    metrics::observe_duration(
                        &metrics::BEACON_BLOCK_GOSSIP_PROPAGATION_VERIFICATION_DELAY_TIME,
                        duration,
                    );
                }

                verified_block
            }
            Err(BlockError::ParentUnknown(block)) => {
                debug!(
                    self.log,
                    "Unknown parent for gossip block";
                    "root" => ?block.canonical_root()
                );
                self.send_sync_message(SyncMessage::UnknownBlock(peer_id, block));
                return;
            }
            Err(e @ BlockError::FutureSlot { .. })
            | Err(e @ BlockError::WouldRevertFinalizedSlot { .. })
            | Err(e @ BlockError::BlockIsAlreadyKnown)
            | Err(e @ BlockError::RepeatProposal { .. })
            | Err(e @ BlockError::NotFinalizedDescendant { .. })
            | Err(e @ BlockError::BeaconChainError(_)) => {
                debug!(self.log, "Could not verify block for gossip, ignoring the block";
                            "error" => %e);
                // Prevent recurring behaviour by penalizing the peer slightly.
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                return;
            }
            Err(e @ BlockError::StateRootMismatch { .. })
            | Err(e @ BlockError::IncorrectBlockProposer { .. })
            | Err(e @ BlockError::BlockSlotLimitReached)
            | Err(e @ BlockError::ProposalSignatureInvalid)
            | Err(e @ BlockError::NonLinearSlots)
            | Err(e @ BlockError::UnknownValidator(_))
            | Err(e @ BlockError::PerBlockProcessingError(_))
            | Err(e @ BlockError::NonLinearParentRoots)
            | Err(e @ BlockError::BlockIsNotLaterThanParent { .. })
            | Err(e @ BlockError::InvalidSignature)
            | Err(e @ BlockError::TooManySkippedSlots { .. })
            | Err(e @ BlockError::WeakSubjectivityConflict)
            | Err(e @ BlockError::InconsistentFork(_))
            | Err(e @ BlockError::GenesisBlock) => {
                warn!(self.log, "Could not verify block for gossip, rejecting the block";
                            "error" => %e);
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
                return;
            }
        };

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_VERIFIED_TOTAL);

        // Register the block with any monitored validators.
        //
        // Run this event *prior* to importing the block, where the block is only partially
        // verified.
        self.chain.validator_monitor.read().register_gossip_block(
            seen_duration,
            verified_block.block.message(),
            verified_block.block_root,
            &self.chain.slot_clock,
        );

        let block_slot = verified_block.block.slot();
        let block_root = verified_block.block_root;

        // Try read the current slot to determine if this block should be imported now or after some
        // delay.
        match self.chain.slot() {
            // We only need to do a simple check about the block slot and the current slot since the
            // `verify_block_for_gossip` function already ensures that the block is within the
            // tolerance for block imports.
            Ok(current_slot) if block_slot > current_slot => {
                warn!(
                    self.log,
                    "Block arrived early";
                    "block_slot" => %block_slot,
                    "block_root" => ?block_root,
                    "msg" => "if this happens consistently, check system clock"
                );

                // Take note of how early this block arrived.
                if let Some(duration) = self
                    .chain
                    .slot_clock
                    .start_of(block_slot)
                    .and_then(|start| start.checked_sub(seen_duration))
                {
                    metrics::observe_duration(
                        &metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_EARLY_SECONDS,
                        duration,
                    );
                }

                metrics::inc_counter(&metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_REQUEUED_TOTAL);

                if reprocess_tx
                    .try_send(ReprocessQueueMessage::EarlyBlock(QueuedBlock {
                        peer_id,
                        block: verified_block,
                        seen_timestamp: seen_duration,
                    }))
                    .is_err()
                {
                    error!(
                        self.log,
                        "Failed to defer block import";
                        "block_slot" => %block_slot,
                        "block_root" => ?block_root,
                        "location" => "block gossip"
                    )
                }
            }
            Ok(_) => self.process_gossip_verified_block(
                peer_id,
                verified_block,
                reprocess_tx,
                seen_duration,
            ),
            Err(e) => {
                error!(
                    self.log,
                    "Failed to defer block import";
                    "error" => ?e,
                    "block_slot" => %block_slot,
                    "block_root" => ?block_root,
                    "location" => "block gossip"
                )
            }
        }
    }

    /// Process the beacon block that has already passed gossip verification.
    ///
    /// Raises a log if there are errors.
    pub fn process_gossip_verified_block(
        self,
        peer_id: PeerId,
        verified_block: GossipVerifiedBlock<T>,
        reprocess_tx: mpsc::Sender<ReprocessQueueMessage<T>>,
        // This value is not used presently, but it might come in handy for debugging.
        _seen_duration: Duration,
    ) {
        let block = Box::new(verified_block.block.clone());

        match self.chain.process_block(verified_block) {
            Ok(block_root) => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_IMPORTED_TOTAL);

                if reprocess_tx
                    .try_send(ReprocessQueueMessage::BlockImported(block_root))
                    .is_err()
                {
                    error!(
                        self.log,
                        "Failed to inform block import";
                        "source" => "gossip",
                        "block_root" => ?block_root,
                    )
                };

                trace!(
                    self.log,
                    "Gossipsub block processed";
                    "peer_id" => %peer_id
                );

                match self.chain.fork_choice() {
                    Ok(()) => trace!(
                        self.log,
                        "Fork choice success";
                        "location" => "block gossip"
                    ),
                    Err(e) => error!(
                        self.log,
                        "Fork choice failed";
                        "error" => ?e,
                        "location" => "block gossip"
                    ),
                }
            }
            Err(BlockError::ParentUnknown { .. }) => {
                // Inform the sync manager to find parents for this block
                // This should not occur. It should be checked by `should_forward_block`
                error!(
                    self.log,
                    "Block with unknown parent attempted to be processed";
                    "peer_id" => %peer_id
                );
                self.send_sync_message(SyncMessage::UnknownBlock(peer_id, block));
            }
            other => {
                debug!(
                    self.log,
                    "Invalid gossip beacon block";
                    "outcome" => ?other,
                    "block root" => ?block.canonical_root(),
                    "block slot" => block.slot()
                );
                self.gossip_penalize_peer(peer_id, PeerAction::MidToleranceError);
                trace!(
                    self.log,
                    "Invalid gossip beacon block ssz";
                    "ssz" => format_args!("0x{}", hex::encode(block.as_ssz_bytes())),
                );
            }
        };
    }

    pub fn process_gossip_voluntary_exit(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: SignedVoluntaryExit,
    ) {
        let validator_index = voluntary_exit.message.validator_index;

        let exit = match self.chain.verify_voluntary_exit_for_gossip(voluntary_exit) {
            Ok(ObservationOutcome::New(exit)) => exit,
            Ok(ObservationOutcome::AlreadyKnown) => {
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                debug!(
                    self.log,
                    "Dropping exit for already exiting validator";
                    "validator_index" => validator_index,
                    "peer" => %peer_id
                );
                return;
            }
            Err(e) => {
                debug!(
                    self.log,
                    "Dropping invalid exit";
                    "validator_index" => validator_index,
                    "peer" => %peer_id,
                    "error" => ?e
                );
                // These errors occur due to a fault in the beacon chain. It is not necessarily
                // the fault on the peer.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                // We still penalize a peer slightly to prevent overuse of invalids.
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
                return;
            }
        };

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_EXIT_VERIFIED_TOTAL);

        self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

        // Register the exit with any monitored validators.
        self.chain
            .validator_monitor
            .read()
            .register_gossip_voluntary_exit(&exit.as_inner().message);

        self.chain.import_voluntary_exit(exit);

        debug!(self.log, "Successfully imported voluntary exit");

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_EXIT_IMPORTED_TOTAL);
    }

    pub fn process_gossip_proposer_slashing(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: ProposerSlashing,
    ) {
        let validator_index = proposer_slashing.signed_header_1.message.proposer_index;

        let slashing = match self
            .chain
            .verify_proposer_slashing_for_gossip(proposer_slashing)
        {
            Ok(ObservationOutcome::New(slashing)) => slashing,
            Ok(ObservationOutcome::AlreadyKnown) => {
                debug!(
                    self.log,
                    "Dropping proposer slashing";
                    "reason" => "Already seen a proposer slashing for that validator",
                    "validator_index" => validator_index,
                    "peer" => %peer_id
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                return;
            }
            Err(e) => {
                // This is likely a fault with the beacon chain and not necessarily a
                // malicious message from the peer.
                debug!(
                    self.log,
                    "Dropping invalid proposer slashing";
                    "validator_index" => validator_index,
                    "peer" => %peer_id,
                    "error" => ?e
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);

                // Penalize peer slightly for invalids.
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
                return;
            }
        };

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_PROPOSER_SLASHING_VERIFIED_TOTAL);

        self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

        // Register the slashing with any monitored validators.
        self.chain
            .validator_monitor
            .read()
            .register_gossip_proposer_slashing(slashing.as_inner());

        self.chain.import_proposer_slashing(slashing);
        debug!(self.log, "Successfully imported proposer slashing");

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_PROPOSER_SLASHING_IMPORTED_TOTAL);
    }

    pub fn process_gossip_attester_slashing(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: AttesterSlashing<T::EthSpec>,
    ) {
        let slashing = match self
            .chain
            .verify_attester_slashing_for_gossip(attester_slashing)
        {
            Ok(ObservationOutcome::New(slashing)) => slashing,
            Ok(ObservationOutcome::AlreadyKnown) => {
                debug!(
                    self.log,
                    "Dropping attester slashing";
                    "reason" => "Slashings already known for all slashed validators",
                    "peer" => %peer_id
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                return;
            }
            Err(e) => {
                debug!(
                    self.log,
                    "Dropping invalid attester slashing";
                    "peer" => %peer_id,
                    "error" => ?e
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                // Penalize peer slightly for invalids.
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
                return;
            }
        };

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_ATTESTER_SLASHING_VERIFIED_TOTAL);

        self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

        // Register the slashing with any monitored validators.
        self.chain
            .validator_monitor
            .read()
            .register_gossip_attester_slashing(slashing.as_inner());

        if let Err(e) = self.chain.import_attester_slashing(slashing) {
            debug!(self.log, "Error importing attester slashing"; "error" => ?e);
            metrics::inc_counter(&metrics::BEACON_PROCESSOR_ATTESTER_SLASHING_ERROR_TOTAL);
        } else {
            debug!(self.log, "Successfully imported attester slashing");
            metrics::inc_counter(&metrics::BEACON_PROCESSOR_ATTESTER_SLASHING_IMPORTED_TOTAL);
        }
    }

    /// Process the sync committee signature received from the gossip network and:
    ///
    /// - If it passes gossip propagation criteria, tell the network thread to forward it.
    /// - Attempt to add it to the naive aggregation pool.
    ///
    /// Raises a log if there are errors.
    pub fn process_gossip_sync_committee_signature(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        sync_signature: SyncCommitteeMessage,
        subnet_id: SyncSubnetId,
        seen_timestamp: Duration,
    ) {
        let sync_signature = match self
            .chain
            .verify_sync_committee_message_for_gossip(sync_signature, subnet_id)
        {
            Ok(sync_signature) => sync_signature,
            Err(e) => {
                self.handle_sync_committee_message_failure(
                    peer_id,
                    message_id,
                    "sync_signature",
                    e,
                );
                return;
            }
        };

        // Indicate to the `Network` service that this message is valid and can be
        // propagated on the gossip network.
        self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

        // Register the sync signature with any monitored validators.
        self.chain
            .validator_monitor
            .read()
            .register_gossip_sync_committee_message(
                seen_timestamp,
                sync_signature.sync_message(),
                &self.chain.slot_clock,
            );

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_SYNC_MESSAGE_VERIFIED_TOTAL);

        if let Err(e) = self
            .chain
            .add_to_naive_sync_aggregation_pool(sync_signature)
        {
            debug!(
                self.log,
                "Sync committee signature invalid for agg pool";
                "reason" => ?e,
                "peer" => %peer_id,
            )
        }

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_SYNC_MESSAGE_IMPORTED_TOTAL);
    }

    /// Process the sync committee contribution received from the gossip network and:
    ///
    /// - If it passes gossip propagation criteria, tell the network thread to forward it.
    /// - Attempt to add it to the block inclusion pool.
    ///
    /// Raises a log if there are errors.
    pub fn process_sync_committee_contribution(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        sync_contribution: SignedContributionAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) {
        let sync_contribution = match self
            .chain
            .verify_sync_contribution_for_gossip(sync_contribution)
        {
            Ok(sync_contribution) => sync_contribution,
            Err(e) => {
                // Report the failure to gossipsub
                self.handle_sync_committee_message_failure(
                    peer_id,
                    message_id,
                    "sync_contribution",
                    e,
                );
                return;
            }
        };

        // Indicate to the `Network` service that this message is valid and can be
        // propagated on the gossip network.
        self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

        self.chain
            .validator_monitor
            .read()
            .register_gossip_sync_committee_contribution(
                seen_timestamp,
                sync_contribution.aggregate(),
                sync_contribution.participant_pubkeys(),
                &self.chain.slot_clock,
            );
        metrics::inc_counter(&metrics::BEACON_PROCESSOR_SYNC_CONTRIBUTION_VERIFIED_TOTAL);

        if let Err(e) = self
            .chain
            .add_contribution_to_block_inclusion_pool(sync_contribution)
        {
            debug!(
                self.log,
                "Sync contribution invalid for op pool";
                "reason" => ?e,
                "peer" => %peer_id,
            )
        }
        metrics::inc_counter(&metrics::BEACON_PROCESSOR_SYNC_CONTRIBUTION_IMPORTED_TOTAL);
    }

    /// Handle an error whilst verifying an `Attestation` or `SignedAggregateAndProof` from the
    /// network.
    fn handle_attestation_verification_failure(
        &self,
        peer_id: PeerId,
        message_id: MessageId,
        failed_att: FailedAtt<T::EthSpec>,
        reprocess_tx: Option<mpsc::Sender<ReprocessQueueMessage<T>>>,
        error: AttnError,
    ) {
        let beacon_block_root = failed_att.beacon_block_root();
        let attestation_type = failed_att.kind();
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
                trace!(
                    self.log,
                    "Attestation is not within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots";
                    "peer_id" => %peer_id,
                    "block" => ?beacon_block_root,
                    "type" => ?attestation_type,
                );

                // Peers that are slow or not to spec can spam us with these messages draining our
                // bandwidth. We therefore penalize these peers when they do this.
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);

                // Do not propagate these messages.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
            }
            AttnError::InvalidSelectionProof { .. } | AttnError::InvalidSignature => {
                /*
                 * These errors are caused by invalid signatures.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::EmptyAggregationBitfield => {
                /*
                 * The aggregate had no signatures and is therefore worthless.
                 *
                 * This is forbidden by the p2p spec. Reject the message.
                 *
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
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
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
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
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::AttestationAlreadyKnown { .. } => {
                /*
                 * The aggregate attestation has already been observed on the network or in
                 * a block.
                 *
                 * The peer is not necessarily faulty.
                 */
                trace!(
                    self.log,
                    "Attestation already known";
                    "peer_id" => %peer_id,
                    "block" => ?beacon_block_root,
                    "type" => ?attestation_type,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
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
                    self.log,
                    "Aggregator already known";
                    "peer_id" => %peer_id,
                    "block" => ?beacon_block_root,
                    "type" => ?attestation_type,
                );
                // This is an allowed behaviour.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);

                return;
            }
            AttnError::PriorAttestationKnown {
                validator_index,
                epoch,
            } => {
                /*
                 * We have already seen an attestation from this validator for this epoch.
                 *
                 * The peer is not necessarily faulty.
                 */
                debug!(
                    self.log,
                    "Prior attestation known";
                    "peer_id" => %peer_id,
                    "block" => ?beacon_block_root,
                    "epoch" => %epoch,
                    "validator_index" => validator_index,
                    "type" => ?attestation_type,
                );

                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);

                return;
            }
            AttnError::ValidatorIndexTooHigh(_) => {
                /*
                 * The aggregator index (or similar field) was higher than the maximum
                 * possible number of validators.
                 *
                 * The peer has published an invalid consensus message.
                 */
                debug!(
                    self.log,
                    "Validation Index too high";
                    "peer_id" => %peer_id,
                    "block" => ?beacon_block_root,
                    "type" => ?attestation_type,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::UnknownHeadBlock { beacon_block_root } => {
                trace!(
                    self.log,
                    "Attestation for unknown block";
                    "peer_id" => %peer_id,
                    "block" => ?beacon_block_root
                );
                if let Some(sender) = reprocess_tx {
                    // We don't know the block, get the sync manager to handle the block lookup, and
                    // send the attestation to be scheduled for re-processing.
                    self.sync_tx
                        .send(SyncMessage::UnknownBlockHash(peer_id, *beacon_block_root))
                        .unwrap_or_else(|_| {
                            warn!(
                                self.log,
                                "Failed to send to sync service";
                                "msg" => "UnknownBlockHash"
                            )
                        });
                    let msg = match failed_att {
                        FailedAtt::Aggregate {
                            attestation,
                            seen_timestamp,
                        } => {
                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_REQUEUED_TOTAL,
                            );
                            ReprocessQueueMessage::UnknownBlockAggregate(QueuedAggregate {
                                peer_id,
                                message_id,
                                attestation,
                                seen_timestamp,
                            })
                        }
                        FailedAtt::Unaggregate {
                            attestation,
                            subnet_id,
                            should_import,
                            seen_timestamp,
                        } => {
                            metrics::inc_counter(
                                &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_REQUEUED_TOTAL,
                            );
                            ReprocessQueueMessage::UnknownBlockUnaggregate(QueuedUnaggregate {
                                peer_id,
                                message_id,
                                attestation,
                                subnet_id,
                                should_import,
                                seen_timestamp,
                            })
                        }
                    };

                    if sender.try_send(msg).is_err() {
                        error!(
                            self.log,
                            "Failed to send attestation for re-processing";
                        )
                    }
                } else {
                    // We shouldn't make any further attempts to process this attestation.
                    // Downscore the peer.
                    self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
                    self.propagate_validation_result(
                        message_id,
                        peer_id,
                        MessageAcceptance::Ignore,
                    );
                }

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
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::BadTargetEpoch => {
                /*
                 * The aggregator index (or similar field) was higher than the maximum
                 * possible number of validators.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::NoCommitteeForSlotAndIndex { .. } => {
                /*
                 * It is not possible to attest this the given committee in the given slot.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::NotExactlyOneAggregationBitSet(_) => {
                /*
                 * The unaggregated attestation doesn't have only one signature.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::AttestsToFutureBlock { .. } => {
                /*
                 * The beacon_block_root is from a higher slot than the attestation.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::InvalidSubnetId { received, expected } => {
                /*
                 * The attestation was received on an incorrect subnet id.
                 */
                debug!(
                    self.log,
                    "Received attestation on incorrect subnet";
                    "expected" => ?expected,
                    "received" => ?received,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::Invalid(_) => {
                /*
                 * The attestation failed the state_processing verification.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::InvalidTargetEpoch { .. } => {
                /*
                 * The attestation is malformed.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::InvalidTargetRoot { .. } => {
                /*
                 * The attestation is malformed.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
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
                    self.log,
                    "Rejected long skip slot attestation";
                    "head_block_slot" => head_block_slot,
                    "attestation_slot" => attestation_slot,
                );
                // In this case we wish to penalize gossipsub peers that do this to avoid future
                // attestations that have too many skip slots.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::MidToleranceError);
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
                    self.log,
                    "Unable to validate aggregate";
                    "peer_id" => %peer_id,
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                // Penalize the peer slightly
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
            }
        }

        debug!(
            self.log,
            "Invalid attestation from network";
            "reason" => ?error,
            "block" => ?beacon_block_root,
            "peer_id" => %peer_id,
            "type" => ?attestation_type,
        );
    }

    /// Handle an error whilst verifying a `SyncCommitteeMessage` or `SignedContributionAndProof` from the
    /// network.
    pub fn handle_sync_committee_message_failure(
        &self,
        peer_id: PeerId,
        message_id: MessageId,
        message_type: &str,
        error: SyncCommitteeError,
    ) {
        metrics::register_sync_committee_error(&error);

        match &error {
            SyncCommitteeError::FutureSlot { .. } | SyncCommitteeError::PastSlot { .. } => {
                /*
                 * These errors can be triggered by a mismatch between our slot and the peer.
                 *
                 *
                 * The peer has published an invalid consensus message, _only_ if we trust our own clock.
                 */
                trace!(
                    self.log,
                    "Sync committee message is not within the last MAXIMUM_GOSSIP_CLOCK_DISPARITY slots";
                    "peer_id" => %peer_id,
                    "type" => ?message_type,
                );

                // Unlike attestations, we have a zero slot buffer in case of sync committee messages,
                // so we don't penalize heavily.
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);

                // Do not propagate these messages.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
            }
            SyncCommitteeError::EmptyAggregationBitfield => {
                /*
                 * The aggregate had no signatures and is therefore worthless.
                 *
                 * This is forbidden by the p2p spec. Reject the message.
                 *
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::InvalidSelectionProof { .. }
            | SyncCommitteeError::InvalidSignature => {
                /*
                 * These errors are caused by invalid signatures.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::AggregatorNotInCommittee { .. }
            | SyncCommitteeError::AggregatorPubkeyUnknown(_) => {
                /*
                * The aggregator is not in the committee for the given `ContributionAndSync` OR
                  The aggregator index was higher than any known validator index
                *
                * The peer has published an invalid consensus message.
                */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::SyncContributionAlreadyKnown(_)
            | SyncCommitteeError::AggregatorAlreadyKnown(_) => {
                /*
                 * The sync committee message already been observed on the network or in
                 * a block.
                 *
                 * The peer is not necessarily faulty.
                 */
                trace!(
                    self.log,
                    "Sync committee message is already known";
                    "peer_id" => %peer_id,
                    "type" => ?message_type,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                return;
            }
            SyncCommitteeError::UnknownValidatorIndex(_) => {
                /*
                 * The aggregator index (or similar field) was higher than the maximum
                 * possible number of validators.
                 *
                 * The peer has published an invalid consensus message.
                 */
                debug!(
                    self.log,
                    "Validation Index too high";
                    "peer_id" => %peer_id,
                    "type" => ?message_type,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::UnknownValidatorPubkey(_) => {
                debug!(
                    self.log,
                    "Validator pubkey is unknown";
                    "peer_id" => %peer_id,
                    "type" => ?message_type,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::InvalidSubnetId { received, expected } => {
                /*
                 * The sync committee message was received on an incorrect subnet id.
                 */
                debug!(
                    self.log,
                    "Received sync committee message on incorrect subnet";
                    "expected" => ?expected,
                    "received" => ?received,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::Invalid(_) => {
                /*
                 * The sync committee message failed the state_processing verification.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::PriorSyncCommitteeMessageKnown { .. } => {
                /*
                 * We have already seen a sync committee message from this validator for this epoch.
                 *
                 * The peer is not necessarily faulty.
                 */
                debug!(
                    self.log,
                    "Prior sync committee message known";
                    "peer_id" => %peer_id,
                    "type" => ?message_type,
                );
                // We still penalize the peer slightly. We don't want this to be a recurring
                // behaviour.
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);

                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);

                return;
            }
            SyncCommitteeError::BeaconChainError(e) => {
                /*
                 * Lighthouse hit an unexpected error whilst processing the sync committee message. It
                 * should be impossible to trigger a `BeaconChainError` from the network,
                 * so we have a bug.
                 *
                 * It's not clear if the message is invalid/malicious.
                 */
                error!(
                    self.log,
                    "Unable to validate sync committee message";
                    "peer_id" => %peer_id,
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                // Penalize the peer slightly
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
            }
            SyncCommitteeError::BeaconStateError(e) => {
                /*
                 * Lighthouse hit an unexpected error whilst processing the sync committee message. It
                 * should be impossible to trigger a `BeaconStateError` from the network,
                 * so we have a bug.
                 *
                 * It's not clear if the message is invalid/malicious.
                 */
                error!(
                    self.log,
                    "Unable to validate sync committee message";
                    "peer_id" => %peer_id,
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                // Penalize the peer slightly
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
            }
            SyncCommitteeError::ContributionError(e) => {
                error!(
                    self.log,
                    "Error while processing sync contribution";
                    "peer_id" => %peer_id,
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                // Penalize the peer slightly
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
            }
            SyncCommitteeError::SyncCommitteeError(e) => {
                error!(
                    self.log,
                    "Error while processing sync committee message";
                    "peer_id" => %peer_id,
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                // Penalize the peer slightly
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);
            }
            SyncCommitteeError::ArithError(e) => {
                /*
                This would most likely imply incompatible configs or an invalid message.
                */
                error!(
                    self.log,
                    "Arithematic error while processing sync committee message";
                    "peer_id" => %peer_id,
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            SyncCommitteeError::InvalidSubcommittee { .. } => {
                /*
                The subcommittee index is higher than `SYNC_COMMITTEE_SUBNET_COUNT`. This would imply
                an invalid message.
                */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
        }
        debug!(
            self.log,
            "Invalid sync committee message from network";
            "reason" => ?error,
            "peer_id" => %peer_id,
            "type" => ?message_type,
        );
    }
}
