use std::sync::Arc;

use educe::Educe;
use eth2::types::{EventKind, SseExecutionPayloadGossip};
use parking_lot::{Mutex, RwLock};
use store::DatabaseBlock;
use tracing::debug;
use tree_hash::TreeHash;
use types::{
    ChainSpec, EthSpec, ExecutionPayloadBid, ExecutionPayloadEnvelope, Hash256, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope, Slot, consts::gloas::BUILDER_INDEX_SELF_BUILD,
};

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BeaconStore, ServerSentEventHandler,
    beacon_proposer_cache::{self, BeaconProposerCache},
    canonical_head::CanonicalHead,
    payload_envelope_verification::{
        EnvelopeError, EnvelopeProcessingSnapshot, load_snapshot_from_state_root,
    },
    validator_pubkey_cache::ValidatorPubkeyCache,
};

/// Bundles only the dependencies needed for gossip verification of execution payload envelopes,
/// decoupling `GossipVerifiedEnvelope::new` from the full `BeaconChain`.
pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub store: &'a BeaconStore<T>,
    pub spec: &'a ChainSpec,
    pub beacon_proposer_cache: &'a Mutex<BeaconProposerCache>,
    pub validator_pubkey_cache: &'a RwLock<ValidatorPubkeyCache<T>>,
    pub genesis_validators_root: Hash256,
    pub event_handler: &'a Option<ServerSentEventHandler<T::EthSpec>>,
}

/// Verify that an execution payload envelope is consistent with its beacon block
/// and execution bid.
pub(crate) fn verify_envelope_consistency<E: EthSpec>(
    envelope: &ExecutionPayloadEnvelope<E>,
    block: &SignedBeaconBlock<E>,
    execution_bid: &ExecutionPayloadBid<E>,
    latest_finalized_slot: Slot,
) -> Result<(), EnvelopeError> {
    // Check that the envelope's slot isn't from a slot prior
    // to the latest finalized slot.
    if envelope.slot() < latest_finalized_slot {
        return Err(EnvelopeError::PriorToFinalization {
            payload_slot: envelope.slot(),
            latest_finalized_slot,
        });
    }

    // Check that the slot of the envelope matches the slot of the block.
    if envelope.slot() != block.slot() {
        return Err(EnvelopeError::SlotMismatch {
            block: block.slot(),
            envelope: envelope.slot(),
        });
    }

    // Builder index matches committed bid.
    if envelope.builder_index != execution_bid.builder_index {
        return Err(EnvelopeError::BuilderIndexMismatch {
            committed_bid: execution_bid.builder_index,
            envelope: envelope.builder_index,
        });
    }

    // The block hash should match the block hash of the execution bid.
    if envelope.payload.block_hash != execution_bid.block_hash {
        return Err(EnvelopeError::BlockHashMismatch {
            committed_bid: execution_bid.block_hash,
            envelope: envelope.payload.block_hash,
        });
    }

    let requests = &envelope.execution_requests;
    if requests.withdrawals.len() > E::max_withdrawal_requests_per_payload() {
        return Err(EnvelopeError::OperationListTooLong {
            kind: "withdrawal_requests",
            length: requests.withdrawals.len(),
            max: E::max_withdrawal_requests_per_payload(),
        });
    }
    if requests.consolidations.len() > E::max_consolidation_requests_per_payload() {
        return Err(EnvelopeError::OperationListTooLong {
            kind: "consolidation_requests",
            length: requests.consolidations.len(),
            max: E::max_consolidation_requests_per_payload(),
        });
    }
    if requests.builder_deposits.len() > E::max_builder_deposit_requests_per_payload() {
        return Err(EnvelopeError::OperationListTooLong {
            kind: "builder_deposit_requests",
            length: requests.builder_deposits.len(),
            max: E::max_builder_deposit_requests_per_payload(),
        });
    }
    if requests.builder_exits.len() > E::max_builder_exit_requests_per_payload() {
        return Err(EnvelopeError::OperationListTooLong {
            kind: "builder_exit_requests",
            length: requests.builder_exits.len(),
            max: E::max_builder_exit_requests_per_payload(),
        });
    }
    if envelope.payload.withdrawals.len() > E::max_withdrawals_per_payload() {
        return Err(EnvelopeError::OperationListTooLong {
            kind: "withdrawals",
            length: envelope.payload.withdrawals.len(),
            max: E::max_withdrawals_per_payload(),
        });
    }

    // The SSZ root of the envelope's execution requests must match the committed bid, per
    // `verify_execution_payload_envelope` in the spec.
    let execution_requests_root = requests.tree_hash_root();
    if execution_requests_root != execution_bid.execution_requests_root {
        return Err(EnvelopeError::ExecutionRequestsRootMismatch {
            committed_bid: execution_bid.execution_requests_root,
            envelope: execution_requests_root,
        });
    }

    Ok(())
}

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
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, EnvelopeError> {
        let envelope = &signed_envelope.message;
        let beacon_block_root = envelope.beacon_block_root;

        // Check that we've seen the beacon block for this envelope and that it passes validation.
        // TODO(EIP-7732): We might need some type of status table in order to differentiate between:
        // If we have a block_processing_table, we could have a Processed(Bid, bool) state that is only
        // entered post adding to fork choice. That way, we could potentially need only a single call to make
        // sure the block is valid and to do all consequent checks with the bid
        //
        // 1. Blocks we haven't seen (IGNORE), and
        // 2. Blocks we've seen that are invalid (REJECT).
        //
        // Presently these two cases are conflated.
        let fork_choice_read_lock = ctx.canonical_head.fork_choice_read_lock();
        let Some(proto_block) = fork_choice_read_lock.get_block(&beacon_block_root) else {
            return Err(EnvelopeError::BlockRootUnknown {
                block_root: beacon_block_root,
            });
        };

        drop(fork_choice_read_lock);

        let latest_finalized_slot = ctx
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // TODO(EIP-7732): check that we haven't seen another valid `SignedExecutionPayloadEnvelope`
        //                 for this block root from this builder - envelope status table check
        let block = match ctx.store.try_get_full_block(&beacon_block_root)? {
            Some(DatabaseBlock::Full(block)) => Arc::new(block),
            Some(DatabaseBlock::Blinded(_)) | None => {
                return Err(EnvelopeError::from(BeaconChainError::MissingBeaconBlock(
                    beacon_block_root,
                )));
            }
        };
        let execution_bid = &block
            .message()
            .body()
            .signed_execution_payload_bid()?
            .message;

        verify_envelope_consistency(envelope, &block, execution_bid, latest_finalized_slot)?;

        // Verify the envelope signature.
        //
        // For self-built envelopes, we can use the proposer cache for the fork and the
        // validator pubkey cache for the proposer's pubkey, avoiding a state load from disk.
        // For external builder envelopes, we must load the state to access the builder registry.
        let builder_index = envelope.builder_index;
        let block_slot = envelope.slot();
        let envelope_epoch = block_slot.epoch(T::EthSpec::slots_per_epoch());
        // Since the payload's block is already guaranteed to be imported, the associated `proto_block.current_epoch_shuffling_id`
        // already carries the correct `shuffling_decision_block`.
        let proposer_shuffling_decision_block = proto_block
            .current_epoch_shuffling_id
            .shuffling_decision_block;

        let (signature_is_valid, opt_snapshot) = if builder_index == BUILDER_INDEX_SELF_BUILD {
            // Fast path: self-built envelopes can be verified without loading the state.
            let mut opt_snapshot = None;
            let proposer = beacon_proposer_cache::with_proposer_cache(
                ctx.beacon_proposer_cache,
                proposer_shuffling_decision_block,
                envelope_epoch,
                |proposers| proposers.get_slot::<T::EthSpec>(block_slot),
                || {
                    debug!(
                        %beacon_block_root,
                        "Proposer shuffling cache miss for envelope verification"
                    );
                    let snapshot = load_snapshot_from_state_root::<T>(
                        beacon_block_root,
                        proto_block.state_root,
                        ctx.store,
                    )?;
                    opt_snapshot = Some(Box::new(snapshot.clone()));
                    Ok::<_, EnvelopeError>((snapshot.state_root, snapshot.pre_state))
                },
                ctx.spec,
            )?;
            let expected_proposer = proposer.index;
            let fork = proposer.fork;

            if block.message().proposer_index() != expected_proposer as u64 {
                return Err(EnvelopeError::IncorrectBlockProposer {
                    proposer_index: block.message().proposer_index(),
                    local_shuffling: expected_proposer as u64,
                });
            }

            let pubkey_cache = ctx.validator_pubkey_cache.read();
            let pubkey = pubkey_cache
                .get(block.message().proposer_index() as usize)
                .ok_or_else(|| EnvelopeError::UnknownValidator {
                    proposer_index: block.message().proposer_index(),
                })?;
            let is_valid = signed_envelope.verify_signature(
                pubkey,
                &fork,
                ctx.genesis_validators_root,
                ctx.spec,
            );
            (is_valid, opt_snapshot)
        } else {
            // TODO(gloas) if we implement a builder pubkey cache, we'll need to use it here.
            // External builder: must load the state to get the builder pubkey.
            let snapshot = load_snapshot_from_state_root::<T>(
                beacon_block_root,
                proto_block.state_root,
                ctx.store,
            )?;
            let is_valid =
                signed_envelope.verify_signature_with_state(&snapshot.pre_state, ctx.spec)?;
            (is_valid, Some(Box::new(snapshot)))
        };

        if !signature_is_valid {
            return Err(EnvelopeError::BadSignature);
        }

        if let Some(event_handler) = ctx.event_handler.as_ref()
            && event_handler.has_execution_payload_gossip_subscribers()
        {
            event_handler.register(EventKind::ExecutionPayloadGossip(
                SseExecutionPayloadGossip {
                    slot: block.slot(),
                    builder_index,
                    block_hash: signed_envelope.message.payload.block_hash,
                    block_root: beacon_block_root,
                },
            ));
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

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Build a `GossipVerificationContext` from this `BeaconChain` for `GossipVerifiedEnvelope`.
    pub fn payload_envelope_gossip_verification_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            store: &self.store,
            spec: &self.spec,
            beacon_proposer_cache: &self.beacon_proposer_cache,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            genesis_validators_root: self.genesis_validators_root,
            event_handler: &self.event_handler,
        }
    }

    /// Returns `Ok(GossipVerifiedEnvelope)` if the supplied `envelope` should be forwarded onto the
    /// gossip network. The envelope is not imported into the chain, it is just partially verified.
    ///
    /// The returned `GossipVerifiedEnvelope` should be provided to `Self::process_execution_payload_envelope` immediately
    /// after it is returned, unless some other circumstance decides it should not be imported at
    /// all.
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given envelope was invalid, or an error was encountered during verification.
    pub async fn verify_envelope_for_gossip(
        self: &Arc<Self>,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
    ) -> Result<GossipVerifiedEnvelope<T>, EnvelopeError> {
        let chain = self.clone();
        self.task_executor
            .clone()
            .spawn_blocking_handle(
                move || {
                    let slot = envelope.slot();
                    let beacon_block_root = envelope.message.beacon_block_root;

                    let ctx = chain.payload_envelope_gossip_verification_context();
                    match GossipVerifiedEnvelope::new(envelope, &ctx) {
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

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use bls::{PublicKeyBytes, Signature, SignatureBytes};
    use ssz_types::ProgressiveVariableList;
    use types::{
        Address, BeaconBlock, BeaconBlockBodyGloas, BeaconBlockGloas, BuilderDepositRequest,
        BuilderExitRequest, ConsolidationRequest, Eth1Data, EthSpec, ExecutionBlockHash,
        ExecutionPayloadBid, ExecutionPayloadEnvelope, ExecutionPayloadGloas,
        ExecutionRequestsGloas, Graffiti, Hash256, MinimalEthSpec, SignedBeaconBlock,
        SignedExecutionPayloadBid, Slot, SyncAggregate, Withdrawal, WithdrawalRequest,
    };

    use super::verify_envelope_consistency;
    use crate::payload_envelope_verification::EnvelopeError;
    use tree_hash::TreeHash;

    type E = MinimalEthSpec;

    fn make_envelope(
        slot: Slot,
        builder_index: u64,
        block_hash: ExecutionBlockHash,
    ) -> ExecutionPayloadEnvelope<E> {
        ExecutionPayloadEnvelope {
            payload: ExecutionPayloadGloas {
                block_hash,
                slot_number: slot,
                ..ExecutionPayloadGloas::default()
            },
            execution_requests: ExecutionRequestsGloas::default(),
            builder_index,
            beacon_block_root: Hash256::ZERO,
            parent_beacon_block_root: Hash256::ZERO,
        }
    }

    fn make_block(slot: Slot) -> SignedBeaconBlock<E> {
        let block = BeaconBlock::Gloas(BeaconBlockGloas {
            slot,
            proposer_index: 0,
            parent_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            body: BeaconBlockBodyGloas {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::ZERO,
                    block_hash: Hash256::ZERO,
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: ProgressiveVariableList::empty(),
                attester_slashings: ProgressiveVariableList::empty(),
                attestations: ProgressiveVariableList::empty(),
                deposits: ProgressiveVariableList::empty(),
                voluntary_exits: ProgressiveVariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                bls_to_execution_changes: ProgressiveVariableList::empty(),
                parent_execution_requests: ExecutionRequestsGloas::default(),
                signed_execution_payload_bid: SignedExecutionPayloadBid::empty(),
                payload_attestations: ProgressiveVariableList::empty(),
                _phantom: PhantomData,
            },
        });
        SignedBeaconBlock::from_block(block, Signature::empty())
    }

    fn make_bid(builder_index: u64, block_hash: ExecutionBlockHash) -> ExecutionPayloadBid<E> {
        ExecutionPayloadBid {
            builder_index,
            block_hash,
            // Commit to the (default) execution requests carried by `make_envelope`.
            execution_requests_root: ExecutionRequestsGloas::<E>::default().tree_hash_root(),
            ..ExecutionPayloadBid::default()
        }
    }

    #[test]
    fn test_valid_envelope() {
        let slot = Slot::new(10);
        let builder_index = 5;
        let block_hash = ExecutionBlockHash::repeat_byte(0xaa);

        let envelope = make_envelope(slot, builder_index, block_hash);
        let block = make_block(slot);
        let bid = make_bid(builder_index, block_hash);

        assert!(verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0)).is_ok());
    }

    #[test]
    fn test_prior_to_finalization() {
        let slot = Slot::new(5);
        let builder_index = 1;
        let block_hash = ExecutionBlockHash::repeat_byte(0xbb);

        let envelope = make_envelope(slot, builder_index, block_hash);
        let block = make_block(slot);
        let bid = make_bid(builder_index, block_hash);
        let latest_finalized_slot = Slot::new(10);

        let result =
            verify_envelope_consistency::<E>(&envelope, &block, &bid, latest_finalized_slot);
        assert!(matches!(
            result,
            Err(EnvelopeError::PriorToFinalization { .. })
        ));
    }

    #[test]
    fn test_slot_mismatch() {
        let builder_index = 1;
        let block_hash = ExecutionBlockHash::repeat_byte(0xcc);

        let envelope = make_envelope(Slot::new(10), builder_index, block_hash);
        let block = make_block(Slot::new(20));
        let bid = make_bid(builder_index, block_hash);

        let result = verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0));
        assert!(matches!(result, Err(EnvelopeError::SlotMismatch { .. })));
    }

    #[test]
    fn test_builder_index_mismatch() {
        let slot = Slot::new(10);
        let block_hash = ExecutionBlockHash::repeat_byte(0xdd);

        let envelope = make_envelope(slot, 1, block_hash);
        let block = make_block(slot);
        let bid = make_bid(2, block_hash);

        let result = verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0));
        assert!(matches!(
            result,
            Err(EnvelopeError::BuilderIndexMismatch { .. })
        ));
    }

    #[test]
    fn test_parent_beacon_block_root_mismatch() {
        let slot = Slot::new(10);
        let builder_index = 1;
        let block_hash = ExecutionBlockHash::repeat_byte(0xab);

        let mut envelope = make_envelope(slot, builder_index, block_hash);
        // The block's parent root is `Hash256::ZERO`; claim a different parent beacon
        // block root in the envelope.
        envelope.parent_beacon_block_root = Hash256::repeat_byte(0x11);
        let block = make_block(slot);
        let bid = make_bid(builder_index, block_hash);

        // Not a gossip condition; the sync-only rejection is inlined in
        // `RangeSyncBlock` construction.
        assert!(verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0)).is_ok());
    }

    #[test]
    fn test_block_hash_mismatch() {
        let slot = Slot::new(10);
        let builder_index = 1;

        let envelope = make_envelope(slot, builder_index, ExecutionBlockHash::repeat_byte(0xee));
        let block = make_block(slot);
        let bid = make_bid(builder_index, ExecutionBlockHash::repeat_byte(0xff));

        let result = verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0));
        assert!(matches!(
            result,
            Err(EnvelopeError::BlockHashMismatch { .. })
        ));
    }

    #[test]
    fn test_payload_withdrawals_over_limit() {
        let slot = Slot::new(10);
        let builder_index = 1;
        let block_hash = ExecutionBlockHash::repeat_byte(0xaa);

        let mut envelope = make_envelope(slot, builder_index, block_hash);
        let block = make_block(slot);
        let bid = make_bid(builder_index, block_hash);

        let withdrawal = Withdrawal {
            index: 0,
            validator_index: 0,
            address: Address::ZERO,
            amount: 0,
        };
        let max = E::max_withdrawals_per_payload();
        envelope.payload.withdrawals = ProgressiveVariableList::new(vec![withdrawal.clone(); max]);
        assert!(verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0)).is_ok());

        envelope.payload.withdrawals = ProgressiveVariableList::new(vec![withdrawal; max + 1]);
        let result = verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0));
        assert!(matches!(
            result,
            Err(EnvelopeError::OperationListTooLong {
                kind: "withdrawals",
                ..
            })
        ));
    }

    fn assert_requests_list_bound(
        kind: &'static str,
        max: usize,
        set_len: impl Fn(&mut ExecutionRequestsGloas<E>, usize),
    ) {
        let slot = Slot::new(10);
        let builder_index = 1;
        let block_hash = ExecutionBlockHash::repeat_byte(0xaa);

        let mut envelope = make_envelope(slot, builder_index, block_hash);
        let block = make_block(slot);

        set_len(&mut envelope.execution_requests, max);
        let bid = ExecutionPayloadBid {
            builder_index,
            block_hash,
            execution_requests_root: envelope.execution_requests.tree_hash_root(),
            ..ExecutionPayloadBid::default()
        };
        assert!(
            verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0)).is_ok(),
            "{kind} at max should be accepted"
        );

        set_len(&mut envelope.execution_requests, max + 1);
        let result = verify_envelope_consistency::<E>(&envelope, &block, &bid, Slot::new(0));
        assert!(
            matches!(
                result,
                Err(EnvelopeError::OperationListTooLong { kind: k, .. }) if k == kind
            ),
            "{kind} over max should be rejected"
        );
    }

    #[test]
    fn test_execution_requests_over_limit() {
        assert_requests_list_bound(
            "withdrawal_requests",
            E::max_withdrawal_requests_per_payload(),
            |requests, len| {
                let withdrawal_request = WithdrawalRequest {
                    source_address: Address::ZERO,
                    validator_pubkey: PublicKeyBytes::empty(),
                    amount: 0,
                };
                requests.withdrawals = ProgressiveVariableList::new(vec![withdrawal_request; len]);
            },
        );

        assert_requests_list_bound(
            "consolidation_requests",
            E::max_consolidation_requests_per_payload(),
            |requests, len| {
                let consolidation_request = ConsolidationRequest {
                    source_address: Address::ZERO,
                    source_pubkey: PublicKeyBytes::empty(),
                    target_pubkey: PublicKeyBytes::empty(),
                };
                requests.consolidations =
                    ProgressiveVariableList::new(vec![consolidation_request; len]);
            },
        );

        assert_requests_list_bound(
            "builder_deposit_requests",
            E::max_builder_deposit_requests_per_payload(),
            |requests, len| {
                let builder_deposit_request = BuilderDepositRequest {
                    pubkey: PublicKeyBytes::empty(),
                    withdrawal_credentials: Hash256::ZERO,
                    amount: 0,
                    signature: SignatureBytes::empty(),
                };
                requests.builder_deposits =
                    ProgressiveVariableList::new(vec![builder_deposit_request; len]);
            },
        );

        assert_requests_list_bound(
            "builder_exit_requests",
            E::max_builder_exit_requests_per_payload(),
            |requests, len| {
                let builder_exit_request = BuilderExitRequest {
                    source_address: Address::ZERO,
                    pubkey: PublicKeyBytes::empty(),
                };
                requests.builder_exits =
                    ProgressiveVariableList::new(vec![builder_exit_request; len]);
            },
        );
    }
}
