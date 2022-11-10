use crate::{metrics, service::NetworkMessage, sync::SyncMessage};

use beacon_chain::store::Error;
use beacon_chain::{
    attestation_verification::{self, Error as AttnError, VerifiedAttestation},
    observed_operations::ObservationOutcome,
    sync_committee_verification::{self, Error as SyncCommitteeError},
    validator_monitor::get_block_delay_ms,
    BeaconChainError, BeaconChainTypes, BlockError, CountUnrealized, ForkChoiceError,
    GossipVerifiedBlock,
};
use lighthouse_network::{Client, MessageAcceptance, MessageId, PeerAction, PeerId, ReportSource};
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use ssz::Encode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::hot_cold_store::HotColdDBError;
use tokio::sync::mpsc;
use types::{
    Attestation, AttesterSlashing, EthSpec, Hash256, IndexedAttestation, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedContributionAndProof, SignedVoluntaryExit,
    Slot, SubnetId, SyncCommitteeMessage, SyncSubnetId,
};

use super::{
    super::work_reprocessing_queue::{
        QueuedAggregate, QueuedGossipBlock, QueuedUnaggregate, ReprocessQueueMessage,
    },
    Worker,
};
use crate::beacon_processor::DuplicateCache;

/// Set to `true` to introduce stricter penalties for peers who send some types of late consensus
/// messages.
const STRICT_LATE_MESSAGE_PENALTIES: bool = false;

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
impl<T: BeaconChainTypes> VerifiedAttestation<T> for VerifiedUnaggregate<T> {
    fn attestation(&self) -> &Attestation<T::EthSpec> {
        &self.attestation
    }

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }

    fn into_attestation_and_indices(self) -> (Attestation<T::EthSpec>, Vec<u64>) {
        let attestation = *self.attestation;
        let attesting_indices = self.indexed_attestation.attesting_indices.into();
        (attestation, attesting_indices)
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
impl<T: BeaconChainTypes> VerifiedAttestation<T> for VerifiedAggregate<T> {
    fn attestation(&self) -> &Attestation<T::EthSpec> {
        &self.signed_aggregate.message.aggregate
    }

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }

    /// Efficient clone-free implementation that moves out of the `Box`.
    fn into_attestation_and_indices(self) -> (Attestation<T::EthSpec>, Vec<u64>) {
        let attestation = self.signed_aggregate.message.aggregate;
        let attesting_indices = self.indexed_attestation.attesting_indices.into();
        (attestation, attesting_indices)
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
        &self.attestation().data.beacon_block_root
    }

    pub fn kind(&self) -> &'static str {
        match self {
            FailedAtt::Unaggregate { .. } => "unaggregated",
            FailedAtt::Aggregate { .. } => "aggregated",
        }
    }

    pub fn attestation(&self) -> &Attestation<T> {
        match self {
            FailedAtt::Unaggregate { attestation, .. } => attestation,
            FailedAtt::Aggregate { attestation, .. } => &attestation.message.aggregate,
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
    fn gossip_penalize_peer(&self, peer_id: PeerId, action: PeerAction, msg: &'static str) {
        self.send_network_message(NetworkMessage::ReportPeer {
            peer_id,
            action,
            source: ReportSource::Gossipsub,
            msg,
        })
    }

    /// Send a message on `message_tx` that the `message_id` sent by `peer_id` should be propagated on
    /// the gossip network.
    ///
    /// Creates a log if there is an internal error.
    /// Propagates the result of the validation for the given message to the network. If the result
    /// is valid the message gets forwarded to other peers.
    pub(crate) fn propagate_validation_result(
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

                // If the attestation is still timely, propagate it.
                self.propagate_attestation_if_timely(
                    verified_attestation.attestation(),
                    message_id,
                    peer_id,
                );

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
                    seen_timestamp,
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

                // If the attestation is still timely, propagate it.
                self.propagate_attestation_if_timely(
                    verified_aggregate.attestation(),
                    message_id,
                    peer_id,
                );

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

                if let Err(e) = self.chain.add_to_block_inclusion_pool(verified_aggregate) {
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
                    seen_timestamp,
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
    #[allow(clippy::too_many_arguments)]
    pub async fn process_gossip_block(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        reprocess_tx: mpsc::Sender<ReprocessQueueMessage<T>>,
        duplicate_cache: DuplicateCache,
        seen_duration: Duration,
    ) {
        if let Some(gossip_verified_block) = self
            .process_gossip_unverified_block(
                message_id,
                peer_id,
                peer_client,
                block,
                reprocess_tx.clone(),
                seen_duration,
            )
            .await
        {
            let block_root = gossip_verified_block.block_root;
            if let Some(handle) = duplicate_cache.check_and_insert(block_root) {
                self.process_gossip_verified_block(
                    peer_id,
                    gossip_verified_block,
                    reprocess_tx,
                    seen_duration,
                )
                .await;
                // Drop the handle to remove the entry from the cache
                drop(handle);
            } else {
                debug!(
                    self.log,
                    "RPC block is being imported";
                    "block_root" => %block_root,
                );
            }
        }
    }

    /// Process the beacon block received from the gossip network and
    /// if it passes gossip propagation criteria, tell the network thread to forward it.
    ///
    /// Returns the `GossipVerifiedBlock` if verification passes and raises a log if there are errors.
    pub async fn process_gossip_unverified_block(
        &self,
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        reprocess_tx: mpsc::Sender<ReprocessQueueMessage<T>>,
        seen_duration: Duration,
    ) -> Option<GossipVerifiedBlock<T>> {
        let block_delay =
            get_block_delay_ms(seen_duration, block.message(), &self.chain.slot_clock);
        // Log metrics to track delay from other nodes on the network.
        metrics::observe_duration(
            &metrics::BEACON_BLOCK_GOSSIP_SLOT_START_DELAY_TIME,
            block_delay,
        );

        let verification_result = self
            .chain
            .clone()
            .verify_block_for_gossip(block.clone())
            .await;

        let block_root = if let Ok(verified_block) = &verification_result {
            verified_block.block_root
        } else {
            block.canonical_root()
        };

        // Write the time the block was observed into delay cache.
        self.chain.block_times_cache.write().set_time_observed(
            block_root,
            block.slot(),
            seen_duration,
            Some(peer_id.to_string()),
            Some(peer_client.to_string()),
        );

        let verified_block = match verification_result {
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
                    "root" => ?verified_block.block_root
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
                    "root" => ?block_root
                );
                self.send_sync_message(SyncMessage::UnknownBlock(peer_id, block, block_root));
                return None;
            }
            Err(e @ BlockError::BeaconChainError(_)) => {
                debug!(
                    self.log,
                    "Gossip block beacon chain error";
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                return None;
            }
            Err(e @ BlockError::FutureSlot { .. })
            | Err(e @ BlockError::WouldRevertFinalizedSlot { .. })
            | Err(e @ BlockError::BlockIsAlreadyKnown)
            | Err(e @ BlockError::RepeatProposal { .. })
            | Err(e @ BlockError::NotFinalizedDescendant { .. }) => {
                debug!(self.log, "Could not verify block for gossip, ignoring the block";
                            "error" => %e);
                // Prevent recurring behaviour by penalizing the peer slightly.
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "gossip_block_high",
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                return None;
            }
            Err(ref e @ BlockError::ExecutionPayloadError(ref epe)) if !epe.penalize_peer() => {
                debug!(self.log, "Could not verify block for gossip, ignoring the block";
                            "error" => %e);
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
                return None;
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
            | Err(e @ BlockError::ExecutionPayloadError(_))
            // TODO(merge): reconsider peer scoring for this event.
            | Err(e @ BlockError::ParentExecutionPayloadInvalid { .. })
            | Err(e @ BlockError::GenesisBlock) => {
                warn!(self.log, "Could not verify block for gossip, rejecting the block";
                            "error" => %e);
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "gossip_block_low",
                );
                return None;
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
                    .try_send(ReprocessQueueMessage::EarlyBlock(QueuedGossipBlock {
                        peer_id,
                        block: Box::new(verified_block),
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
                None
            }
            Ok(_) => Some(verified_block),
            Err(e) => {
                error!(
                    self.log,
                    "Failed to defer block import";
                    "error" => ?e,
                    "block_slot" => %block_slot,
                    "block_root" => ?block_root,
                    "location" => "block gossip"
                );
                None
            }
        }
    }

    /// Process the beacon block that has already passed gossip verification.
    ///
    /// Raises a log if there are errors.
    pub async fn process_gossip_verified_block(
        self,
        peer_id: PeerId,
        verified_block: GossipVerifiedBlock<T>,
        reprocess_tx: mpsc::Sender<ReprocessQueueMessage<T>>,
        // This value is not used presently, but it might come in handy for debugging.
        _seen_duration: Duration,
    ) {
        let block: Arc<_> = verified_block.block.clone();
        let block_root = verified_block.block_root;

        match self
            .chain
            .process_block(block_root, verified_block, CountUnrealized::True)
            .await
        {
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

                debug!(
                    self.log,
                    "Gossipsub block processed";
                    "block" => ?block_root,
                    "peer_id" => %peer_id
                );

                self.chain.recompute_head_at_current_slot().await;
            }
            Err(BlockError::ParentUnknown { .. }) => {
                // Inform the sync manager to find parents for this block
                // This should not occur. It should be checked by `should_forward_block`
                error!(
                    self.log,
                    "Block with unknown parent attempted to be processed";
                    "peer_id" => %peer_id
                );
                self.send_sync_message(SyncMessage::UnknownBlock(peer_id, block, block_root));
            }
            Err(ref e @ BlockError::ExecutionPayloadError(ref epe)) if !epe.penalize_peer() => {
                debug!(
                    self.log,
                    "Failed to verify execution payload";
                    "error" => %e
                );
            }
            other => {
                debug!(
                    self.log,
                    "Invalid gossip beacon block";
                    "outcome" => ?other,
                    "block root" => ?block_root,
                    "block slot" => block.slot()
                );
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::MidToleranceError,
                    "bad_gossip_block_ssz",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "invalid_gossip_exit",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "invalid_gossip_proposer_slashing",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "invalid_gossip_attester_slashing",
                );
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

        self.chain.import_attester_slashing(slashing);
        debug!(self.log, "Successfully imported attester slashing");
        metrics::inc_counter(&metrics::BEACON_PROCESSOR_ATTESTER_SLASHING_IMPORTED_TOTAL);
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
        let message_slot = sync_signature.slot;
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
                    message_slot,
                    seen_timestamp,
                );
                return;
            }
        };

        // If the message is still timely, propagate it.
        self.propagate_sync_message_if_timely(message_slot, message_id, peer_id);

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
        let contribution_slot = sync_contribution.message.contribution.slot;
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
                    contribution_slot,
                    seen_timestamp,
                );
                return;
            }
        };

        // If the message is still timely, propagate it.
        self.propagate_sync_message_if_timely(contribution_slot, message_id, peer_id);

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
        seen_timestamp: Duration,
    ) {
        let beacon_block_root = failed_att.beacon_block_root();
        let attestation_type = failed_att.kind();
        metrics::register_attestation_error(&error);
        match &error {
            AttnError::FutureSlot { .. } => {
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_future_slot",
                );

                // Do not propagate these messages.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
            }
            AttnError::PastSlot { .. } => {
                // Produce a slot clock frozen at the time we received the message from the
                // network.
                let seen_clock = &self.chain.slot_clock.freeze_at(seen_timestamp);
                let hindsight_verification =
                    attestation_verification::verify_propagation_slot_range(
                        seen_clock,
                        failed_att.attestation(),
                    );

                // Only penalize the peer if it would have been invalid at the moment we received
                // it.
                if STRICT_LATE_MESSAGE_PENALTIES && hindsight_verification.is_err() {
                    self.gossip_penalize_peer(
                        peer_id,
                        PeerAction::LowToleranceError,
                        "attn_past_slot",
                    );
                }

                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
            }
            AttnError::InvalidSelectionProof { .. } | AttnError::InvalidSignature => {
                /*
                 * These errors are caused by invalid signatures.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_selection_proof",
                );
            }
            AttnError::EmptyAggregationBitfield => {
                /*
                 * The aggregate had no signatures and is therefore worthless.
                 *
                 * This is forbidden by the p2p spec. Reject the message.
                 *
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_empty_agg_bitfield",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_agg_pubkey",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_agg_not_in_committee",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_val_index_too_high",
                );
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
                    //
                    // Don't downscore the peer since it's not clear if we requested this head
                    // block from them or not.
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
                 * We should always get `AttnError::UnknownHeadBlock` before we get this
                 * error, so this means we can get this error if:
                 *
                 * 1. The target root does not represent a valid block.
                 * 2. We do not have the target root in our DB.
                 *
                 * For (2), we should only be processing attestations when we should have
                 * all the available information. Note: if we do a weak-subjectivity sync
                 * it's possible that this situation could occur, but I think it's
                 * unlikely. For now, we will declare this to be an invalid message.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_unknown_target",
                );
            }
            AttnError::BadTargetEpoch => {
                /*
                 * The aggregator index (or similar field) was higher than the maximum
                 * possible number of validators.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_bad_target",
                );
            }
            AttnError::NoCommitteeForSlotAndIndex { .. } => {
                /*
                 * It is not possible to attest this the given committee in the given slot.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_no_committee",
                );
            }
            AttnError::NotExactlyOneAggregationBitSet(_) => {
                /*
                 * The unaggregated attestation doesn't have only one signature.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_too_many_agg_bits",
                );
            }
            AttnError::AttestsToFutureBlock { .. } => {
                /*
                 * The beacon_block_root is from a higher slot than the attestation.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_future_block",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_invalid_subnet_id",
                );
            }
            AttnError::Invalid(_) => {
                /*
                 * The attestation failed the state_processing verification.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_invalid_state_processing",
                );
            }
            AttnError::InvalidTargetEpoch { .. } => {
                /*
                 * The attestation is malformed.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_invalid_target_epoch",
                );
            }
            AttnError::InvalidTargetRoot { .. } => {
                /*
                 * The attestation is malformed.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "attn_invalid_target_root",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::MidToleranceError,
                    "attn_too_many_skipped_slots",
                );
            }
            AttnError::HeadBlockFinalized { beacon_block_root } => {
                debug!(
                    self.log,
                    "Ignored attestation to finalized block";
                    "block_root" => ?beacon_block_root,
                    "attestation_slot" => failed_att.attestation().data.slot,
                );

                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);

                // The peer that sent us this could be a lagger, or a spammer, or this failure could
                // be due to us processing attestations extremely slowly. Don't be too harsh.
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "attn_to_finalized_block",
                );
            }
            AttnError::BeaconChainError(BeaconChainError::DBError(Error::HotColdDBError(
                HotColdDBError::AttestationStateIsFinalized { .. },
            ))) => {
                debug!(self.log, "Attestation for finalized state"; "peer_id" => % peer_id);
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
            }
            e @ AttnError::BeaconChainError(BeaconChainError::MaxCommitteePromises(_)) => {
                debug!(
                    self.log,
                    "Dropping attestation";
                    "target_root" => ?failed_att.attestation().data.target.root,
                    "beacon_block_root" => ?beacon_block_root,
                    "slot" => ?failed_att.attestation().data.slot,
                    "type" => ?attestation_type,
                    "error" => ?e,
                    "peer_id" => % peer_id
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
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
                    "Unable to validate attestation";
                    "beacon_block_root" => ?beacon_block_root,
                    "slot" => ?failed_att.attestation().data.slot,
                    "type" => ?attestation_type,
                    "peer_id" => %peer_id,
                    "error" => ?e,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
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
        sync_committee_message_slot: Slot,
        seen_timestamp: Duration,
    ) {
        metrics::register_sync_committee_error(&error);

        match &error {
            SyncCommitteeError::FutureSlot { .. } => {
                /*
                 * This error can be triggered by a mismatch between our slot and the peer.
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "sync_future_slot",
                );

                // Do not propagate these messages.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
            }
            SyncCommitteeError::PastSlot { .. } => {
                /*
                 * This error can be triggered by a mismatch between our slot and the peer.
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

                // Compute the slot when we received the message.
                let received_slot = self
                    .chain
                    .slot_clock
                    .slot_of(seen_timestamp)
                    .unwrap_or_else(|| self.chain.slot_clock.genesis_slot());

                // The message is "excessively" late if it was more than one slot late.
                let excessively_late = received_slot > sync_committee_message_slot + 1;

                // This closure will lazily produce a slot clock frozen at the time we received the
                // message from the network and return a bool indicating if the message was invalid
                // at the time of receipt too.
                let invalid_in_hindsight = || {
                    let seen_clock = &self.chain.slot_clock.freeze_at(seen_timestamp);
                    let hindsight_verification =
                        sync_committee_verification::verify_propagation_slot_range(
                            seen_clock,
                            &sync_committee_message_slot,
                        );
                    hindsight_verification.is_err()
                };

                // Penalize the peer if the message was more than one slot late
                if STRICT_LATE_MESSAGE_PENALTIES && excessively_late && invalid_in_hindsight() {
                    self.gossip_penalize_peer(
                        peer_id,
                        PeerAction::HighToleranceError,
                        "sync_past_slot",
                    );
                }

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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_empty_agg_bitfield",
                );
            }
            SyncCommitteeError::InvalidSelectionProof { .. }
            | SyncCommitteeError::InvalidSignature => {
                /*
                 * These errors are caused by invalid signatures.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_invalid_proof_or_sig",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_bad_aggregator",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_unknown_validator",
                );
            }
            SyncCommitteeError::UnknownValidatorPubkey(_) => {
                debug!(
                    self.log,
                    "Validator pubkey is unknown";
                    "peer_id" => %peer_id,
                    "type" => ?message_type,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_unknown_validator_pubkey",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_invalid_subnet_id",
                );
            }
            SyncCommitteeError::Invalid(_) => {
                /*
                 * The sync committee message failed the state_processing verification.
                 *
                 * The peer has published an invalid consensus message.
                 */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_invalid_state_processing",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "sync_prior_known",
                );

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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "sync_beacon_state_error",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "sync_contribution_error",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::HighToleranceError,
                    "sync_committee_error",
                );
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
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_arith_error",
                );
            }
            SyncCommitteeError::InvalidSubcommittee { .. } => {
                /*
                The subcommittee index is higher than `SYNC_COMMITTEE_SUBNET_COUNT`. This would imply
                an invalid message.
                */
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "sync_invalid_subcommittee",
                );
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

    /// Propagate (accept) if `is_timely == true`, otherwise ignore.
    fn propagate_if_timely(&self, is_timely: bool, message_id: MessageId, peer_id: PeerId) {
        if is_timely {
            // The message is still relevant, propagate.
            self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);
        } else {
            // The message is not relevant, ignore. It might be that this message became irrelevant
            // during the time it took to process it, or it was received invalid.
            self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
        }
    }

    /// If an attestation (agg. or unagg.) is still valid with respect to the current time (i.e.,
    /// timely), propagate it on gossip. Otherwise, ignore it.
    fn propagate_attestation_if_timely(
        &self,
        attestation: &Attestation<T::EthSpec>,
        message_id: MessageId,
        peer_id: PeerId,
    ) {
        let is_timely = attestation_verification::verify_propagation_slot_range(
            &self.chain.slot_clock,
            attestation,
        )
        .is_ok();

        self.propagate_if_timely(is_timely, message_id, peer_id)
    }

    /// If a sync committee signature or sync committee contribution is still valid with respect to
    /// the current time (i.e., timely), propagate it on gossip. Otherwise, ignore it.
    fn propagate_sync_message_if_timely(
        &self,
        sync_message_slot: Slot,
        message_id: MessageId,
        peer_id: PeerId,
    ) {
        let is_timely = self
            .chain
            .slot_clock
            .now()
            .map_or(false, |current_slot| sync_message_slot == current_slot);

        self.propagate_if_timely(is_timely, message_id, peer_id)
    }
}
