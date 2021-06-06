use crate::{metrics, service::NetworkMessage, sync::SyncMessage};

use beacon_chain::{
    attestation_verification::{Error as AttnError, SignatureVerifiedAttestation},
    observed_operations::ObservationOutcome,
    validator_monitor::get_block_delay_ms,
    BeaconChainError, BeaconChainTypes, BlockError, ForkChoiceError, GossipVerifiedBlock,
};
use eth2_libp2p::{MessageAcceptance, MessageId, PeerAction, PeerId, ReportSource};
use slog::{debug, error, info, trace, warn};
use slot_clock::SlotClock;
use ssz::Encode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use types::{
    Attestation, AttesterSlashing, Hash256, ProposerSlashing, SignedAggregateAndProof,
    SignedBeaconBlock, SignedVoluntaryExit, SubnetId,
};

use super::{super::block_delay_queue::QueuedBlock, Worker};

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
    pub fn process_gossip_attestation(
        self,
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Attestation<T::EthSpec>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    ) {
        let beacon_block_root = attestation.data.beacon_block_root;

        let attestation = match self
            .chain
            .verify_unaggregated_attestation_for_gossip(attestation, Some(subnet_id))
        {
            Ok(attestation) => attestation,
            Err(e) => {
                self.handle_attestation_verification_failure(
                    peer_id,
                    message_id,
                    beacon_block_root,
                    "unaggregated",
                    e,
                );
                return;
            }
        };

        // Register the attestation with any monitored validators.
        self.chain
            .validator_monitor
            .read()
            .register_gossip_unaggregated_attestation(
                seen_timestamp,
                attestation.indexed_attestation(),
                &self.chain.slot_clock,
            );

        // Indicate to the `Network` service that this message is valid and can be
        // propagated on the gossip network.
        self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

        if !should_import {
            return;
        }

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_VERIFIED_TOTAL);

        if let Err(e) = self.chain.apply_attestation_to_fork_choice(&attestation) {
            match e {
                BeaconChainError::ForkChoiceError(ForkChoiceError::InvalidAttestation(e)) => {
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

        if let Err(e) = self.chain.add_to_naive_aggregation_pool(attestation) {
            debug!(
                self.log,
                "Attestation invalid for agg pool";
                "reason" => ?e,
                "peer" => %peer_id,
                "beacon_block_root" => ?beacon_block_root
            )
        }

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_IMPORTED_TOTAL);
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
        aggregate: SignedAggregateAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) {
        let beacon_block_root = aggregate.message.aggregate.data.beacon_block_root;

        let aggregate = match self
            .chain
            .verify_aggregated_attestation_for_gossip(aggregate)
        {
            Ok(aggregate) => aggregate,
            Err(e) => {
                // Report the failure to gossipsub
                self.handle_attestation_verification_failure(
                    peer_id,
                    message_id,
                    beacon_block_root,
                    "aggregated",
                    e,
                );
                return;
            }
        };

        // Indicate to the `Network` service that this message is valid and can be
        // propagated on the gossip network.
        self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Accept);

        // Register the attestation with any monitored validators.
        self.chain
            .validator_monitor
            .read()
            .register_gossip_aggregated_attestation(
                seen_timestamp,
                aggregate.aggregate(),
                aggregate.indexed_attestation(),
                &self.chain.slot_clock,
            );

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_VERIFIED_TOTAL);

        if let Err(e) = self.chain.apply_attestation_to_fork_choice(&aggregate) {
            match e {
                BeaconChainError::ForkChoiceError(ForkChoiceError::InvalidAttestation(e)) => {
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

        if let Err(e) = self.chain.add_to_block_inclusion_pool(aggregate) {
            debug!(
                self.log,
                "Attestation invalid for op pool";
                "reason" => ?e,
                "peer" => %peer_id,
                "beacon_block_root" => ?beacon_block_root
            )
        }

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_IMPORTED_TOTAL);
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
        block: SignedBeaconBlock<T::EthSpec>,
        delayed_import_tx: mpsc::Sender<QueuedBlock<T>>,
        seen_duration: Duration,
    ) {
        // Log metrics to track delay from other nodes on the network.
        metrics::observe_duration(
            &metrics::BEACON_BLOCK_GOSSIP_SLOT_START_DELAY_TIME,
            get_block_delay_ms(seen_duration, &block.message, &self.chain.slot_clock),
        );

        let verified_block = match self.chain.verify_block_for_gossip(block) {
            Ok(verified_block) => {
                info!(
                    self.log,
                    "New block received";
                    "slot" => verified_block.block.slot(),
                    "hash" => %verified_block.block_root
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
                    "root" => %block.canonical_root()
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
            &verified_block.block.message,
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
                    "block_root" => %block_root,
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

                if delayed_import_tx
                    .try_send(QueuedBlock {
                        peer_id,
                        block: verified_block,
                        seen_timestamp: seen_duration,
                    })
                    .is_err()
                {
                    error!(
                        self.log,
                        "Failed to defer block import";
                        "block_slot" => %block_slot,
                        "block_root" => %block_root,
                        "location" => "block gossip"
                    )
                }
            }
            Ok(_) => self.process_gossip_verified_block(peer_id, verified_block, seen_duration),
            Err(e) => {
                error!(
                    self.log,
                    "Failed to defer block import";
                    "error" => ?e,
                    "block_slot" => %block_slot,
                    "block_root" => %block_root,
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
        // This value is not used presently, but it might come in handy for debugging.
        _seen_duration: Duration,
    ) {
        let block = Box::new(verified_block.block.clone());

        match self.chain.process_block(verified_block) {
            Ok(_block_root) => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_IMPORTED_TOTAL);

                trace!(
                    self.log,
                    "Gossipsub block processed";
                    "peer_id" => %peer_id
                );

                // The `MessageHandler` would be the place to put this, however it doesn't seem
                // to have a reference to the `BeaconChain`. I will leave this for future
                // works.
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
                    "block root" => %block.canonical_root(),
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

    /// Handle an error whilst verifying an `Attestation` or `SignedAggregateAndProof` from the
    /// network.
    pub fn handle_attestation_verification_failure(
        &self,
        peer_id: PeerId,
        message_id: MessageId,
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
                trace!(
                    self.log,
                    "Attestation is not within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots";
                    "peer_id" => %peer_id,
                    "block" => %beacon_block_root,
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
                 * Whilst we don't gossip this attestation, this act is **not** a clear
                 * violation of the spec nor indication of fault.
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
                    "block" => %beacon_block_root,
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
                    "block" => %beacon_block_root,
                    "type" => ?attestation_type,
                );
                // This is an allowed behaviour.
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);

                return;
            }
            AttnError::PriorAttestationKnown { .. } => {
                /*
                 * We have already seen an attestation from this validator for this epoch.
                 *
                 * The peer is not necessarily faulty.
                 */
                debug!(
                    self.log,
                    "Prior attestation known";
                    "peer_id" => %peer_id,
                    "block" => %beacon_block_root,
                    "type" => ?attestation_type,
                );
                // We still penalize the peer slightly. We don't want this to be a recurring
                // behaviour.
                self.gossip_penalize_peer(peer_id, PeerAction::HighToleranceError);

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
                    "block" => %beacon_block_root,
                    "type" => ?attestation_type,
                );
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Reject);
                self.gossip_penalize_peer(peer_id, PeerAction::LowToleranceError);
            }
            AttnError::UnknownHeadBlock { beacon_block_root } => {
                // Note: its a little bit unclear as to whether or not this block is unknown or
                // just old. See:
                //
                // https://github.com/sigp/lighthouse/issues/1039

                // TODO: Maintain this attestation and re-process once sync completes
                // TODO: We then score based on whether we can download the block and re-process.
                trace!(
                    self.log,
                    "Attestation for unknown block";
                    "peer_id" => %peer_id,
                    "block" => %beacon_block_root
                );
                // we don't know the block, get the sync manager to handle the block lookup
                self.sync_tx
                    .send(SyncMessage::UnknownBlockHash(peer_id, *beacon_block_root))
                    .unwrap_or_else(|_| {
                        warn!(
                            self.log,
                            "Failed to send to sync service";
                            "msg" => "UnknownBlockHash"
                        )
                    });
                self.propagate_validation_result(message_id, peer_id, MessageAcceptance::Ignore);
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
            "block" => %beacon_block_root,
            "peer_id" => %peer_id,
            "type" => ?attestation_type,
        );
    }
}
