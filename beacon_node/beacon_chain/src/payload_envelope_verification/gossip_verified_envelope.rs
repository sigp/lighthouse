use std::sync::Arc;

use educe::Educe;
use slot_clock::SlotClock;
use state_processing::{VerifySignatures, envelope_processing::process_execution_payload_envelope};
use tracing::{Span, debug};
use types::{
    EthSpec, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
    consts::gloas::BUILDER_INDEX_SELF_BUILD,
};

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockError, NotifyExecutionLayer,
    PayloadVerificationOutcome,
    payload_envelope_verification::{
        EnvelopeError, EnvelopeImportData, EnvelopeProcessingSnapshot, ExecutionPendingEnvelope,
        IntoExecutionPendingEnvelope, MaybeAvailableEnvelope, load_snapshot,
        payload_notifier::PayloadNotifier,
    },
};

/// A wrapper around a `SignedExecutionPayloadEnvelope` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Educe)]
#[educe(Debug(bound = "T: BeaconChainTypes"))]
pub struct GossipVerifiedEnvelope<T: BeaconChainTypes> {
    pub signed_envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
    pub block: Arc<SignedBeaconBlock<T::EthSpec>>,
    pub snapshot: Option<Box<EnvelopeProcessingSnapshot<T::EthSpec>>>,
}

impl<T: BeaconChainTypes> GossipVerifiedEnvelope<T> {
    pub fn new(
        signed_envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, EnvelopeError> {
        let envelope = &signed_envelope.message;
        let payload = &envelope.payload;
        let beacon_block_root = envelope.beacon_block_root;

        // Check that we've seen the beacon block for this envelope and that it passes validation.
        // TODO(EIP-7732): We might need some type of status table in order to differentiate between:
        //
        // 1. Blocks we haven't seen (IGNORE), and
        // 2. Blocks we've seen that are invalid (REJECT).
        //
        // Presently these two cases are conflated.
        let fork_choice_read_lock = chain.canonical_head.fork_choice_read_lock();
        let Some(proto_block) = fork_choice_read_lock.get_block(&beacon_block_root) else {
            return Err(EnvelopeError::BlockRootUnknown {
                block_root: beacon_block_root,
            });
        };

        let latest_finalized_slot = fork_choice_read_lock
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        drop(fork_choice_read_lock);

        // TODO(EIP-7732): check that we haven't seen another valid `SignedExecutionPayloadEnvelope`
        //                 for this block root from this builder - envelope status table check
        let block = chain
            .get_full_block(&beacon_block_root)?
            .ok_or_else(|| {
                EnvelopeError::from(BeaconChainError::MissingBeaconBlock(beacon_block_root))
            })
            .map(Arc::new)?;
        let execution_bid = &block
            .message()
            .body()
            .signed_execution_payload_bid()?
            .message;

        // check that the envelopes slot isnt from a slot prior
        // to the latest finalized slot.
        if envelope.slot < latest_finalized_slot {
            return Err(EnvelopeError::PriorToFinalization {
                payload_slot: envelope.slot,
                latest_finalized_slot,
            });
        }

        // check that the slot of the envelope matches the slot of the parent block
        if envelope.slot != block.slot() {
            return Err(EnvelopeError::SlotMismatch {
                block: block.slot(),
                envelope: envelope.slot,
            });
        }

        // builder index matches committed bid
        if envelope.builder_index != execution_bid.builder_index {
            return Err(EnvelopeError::BuilderIndexMismatch {
                committed_bid: execution_bid.builder_index,
                envelope: envelope.builder_index,
            });
        }

        // the block hash should match the block hash of the execution bid
        if payload.block_hash != execution_bid.block_hash {
            return Err(EnvelopeError::BlockHashMismatch {
                committed_bid: execution_bid.block_hash,
                envelope: payload.block_hash,
            });
        }

        // Verify the envelope signature.
        //
        // For self-build envelopes, we can use the proposer cache for the fork and the
        // validator pubkey cache for the proposer's pubkey, avoiding a state load from disk.
        // For external builder envelopes, we must load the state to access the builder registry.
        let builder_index = envelope.builder_index;
        let block_slot = envelope.slot;
        let block_epoch = block_slot.epoch(T::EthSpec::slots_per_epoch());
        let proposer_shuffling_decision_block =
            proto_block.proposer_shuffling_root_for_child_block(block_epoch, &chain.spec);

        let (signature_is_valid, opt_snapshot) = if builder_index == BUILDER_INDEX_SELF_BUILD {
            // Fast path: self-build envelopes can be verified without loading the state.
            let envelope_ref = signed_envelope.as_ref();
            let mut opt_snapshot = None;
            let proposer = chain.with_proposer_cache::<_, EnvelopeError>(
                proposer_shuffling_decision_block,
                block_epoch,
                |proposers| proposers.get_slot::<T::EthSpec>(block_slot),
                || {
                    debug!(
                        %beacon_block_root,
                        "Proposer shuffling cache miss for envelope verification"
                    );
                    let snapshot = load_snapshot(envelope_ref, chain)?;
                    opt_snapshot = Some(Box::new(snapshot.clone()));
                    Ok((snapshot.state_root, snapshot.pre_state))
                },
            )?;
            let fork = proposer.fork;

            let pubkey_cache = chain.validator_pubkey_cache.read();
            let pubkey = pubkey_cache
                .get(block.message().proposer_index() as usize)
                .ok_or_else(|| EnvelopeError::UnknownValidator {
                    builder_index: block.message().proposer_index(),
                })?;
            let is_valid = signed_envelope.verify_signature(
                pubkey,
                &fork,
                chain.genesis_validators_root,
                &chain.spec,
            );
            (is_valid, opt_snapshot)
        } else {
            // TODO(gloas) we should probably introduce a builder cache or some type of
            // global cache.
            // External builder: must load the state to get the builder pubkey.
            let snapshot = load_snapshot(signed_envelope.as_ref(), chain)?;
            let is_valid =
                signed_envelope.verify_signature_with_state(&snapshot.pre_state, &chain.spec)?;
            (is_valid, Some(Box::new(snapshot)))
        };

        if !signature_is_valid {
            return Err(EnvelopeError::BadSignature);
        }

        Ok(Self {
            signed_envelope,
            block,
            snapshot: opt_snapshot,
        })
    }

    pub fn envelope_cloned(&self) -> Arc<SignedExecutionPayloadEnvelope<T::EthSpec>> {
        self.signed_envelope.clone()
    }
}

impl<T: BeaconChainTypes> IntoExecutionPendingEnvelope<T> for GossipVerifiedEnvelope<T> {
    fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T::EthSpec>, BlockError> {
        let signed_envelope = self.signed_envelope;
        let envelope = &signed_envelope.message;
        let payload = &envelope.payload;

        // Verify the execution payload is valid
        let payload_notifier = PayloadNotifier::new(
            chain.clone(),
            signed_envelope.clone(),
            self.block.clone(),
            notify_execution_layer,
        )?;
        let block_root = envelope.beacon_block_root;
        let slot = self.block.slot();

        let payload_verification_future = async move {
            let chain = payload_notifier.chain.clone();
            // TODO:(gloas): timing metrics
            if let Some(started_execution) = chain.slot_clock.now_duration() {
                chain.block_times_cache.write().set_time_started_execution(
                    block_root,
                    slot,
                    started_execution,
                );
            }

            let payload_verification_status = payload_notifier.notify_new_payload().await?;
            Ok(PayloadVerificationOutcome {
                payload_verification_status,
                // This fork is after the merge so it'll never be the merge transition block
                is_valid_merge_transition_block: false,
            })
        };
        // Spawn the payload verification future as a new task, but don't wait for it to complete.
        // The `payload_verification_future` will be awaited later to ensure verification completed
        // successfully.
        let payload_verification_handle = chain
            .task_executor
            .spawn_handle(
                payload_verification_future,
                "execution_payload_verification",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?;

        let snapshot = if let Some(snapshot) = self.snapshot {
            *snapshot
        } else {
            load_snapshot(signed_envelope.as_ref(), chain)?
        };
        let mut state = snapshot.pre_state;

        // All the state modifications are done in envelope_processing
        process_execution_payload_envelope(
            &mut state,
            Some(snapshot.state_root),
            &signed_envelope,
            // verify signature already done for GossipVerifiedEnvelope
            VerifySignatures::False,
            &chain.spec,
        )?;

        Ok(ExecutionPendingEnvelope {
            signed_envelope: MaybeAvailableEnvelope::AvailabilityPending {
                block_hash: payload.block_hash,
                envelope: signed_envelope,
            },
            import_data: EnvelopeImportData {
                block_root,
                block: self.block,
                post_state: Box::new(state),
            },
            payload_verification_handle,
        })
    }

    fn envelope(&self) -> &Arc<SignedExecutionPayloadEnvelope<T::EthSpec>> {
        &self.signed_envelope
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `Ok(GossipVerifiedEnvelope)` if the supplied `envelope` should be forwarded onto the
    /// gossip network. The envelope is not imported into the chain, it is just partially verified.
    ///
    /// The returned `GossipVerifiedEnvelope` should be provided to `Self::process_execution_payload_envelope` immediately
    /// after it is returned, unless some other circumstance decides it should not be imported at
    /// all.
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given envelope was invalid, or an error was encountered during
    pub async fn verify_envelope_for_gossip(
        self: &Arc<Self>,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
    ) -> Result<GossipVerifiedEnvelope<T>, EnvelopeError> {
        let chain = self.clone();
        let span = Span::current();
        self.task_executor
            .clone()
            .spawn_blocking_handle(
                move || {
                    let _guard = span.enter();
                    let slot = envelope.slot();
                    let beacon_block_root = envelope.message.beacon_block_root;

                    match GossipVerifiedEnvelope::new(envelope, &chain) {
                        Ok(verified) => {
                            debug!(
                                %slot,
                                ?beacon_block_root,
                                "Successfully verified gossip envelope"
                            );

                            Ok(verified)
                        }
                        Err(e) => {
                            debug!(
                                error = e.to_string(),
                                ?beacon_block_root,
                                %slot,
                                "Rejected gossip envelope"
                            );

                            Err(e)
                        }
                    }
                },
                "gossip_envelope_verification_handle",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?
            .await
            .map_err(BeaconChainError::TokioJoin)?
    }
}
