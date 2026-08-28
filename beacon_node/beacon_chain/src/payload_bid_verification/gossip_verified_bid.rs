use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainTypes, BeaconStore, CachedHead, CanonicalHead,
    canonical_head::ForkChoiceReadGuard,
    payload_bid_verification::{
        PayloadBidError,
        payload_bid_cache::{BidParent, GossipVerifiedPayloadBidCache},
    },
    proposer_preferences_verification::proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
};
use educe::Educe;
use eth2::types::{EventKind, ForkVersionedResponse};
use slot_clock::SlotClock;
use state_processing::signature_sets::{
    execution_payload_bid_signature_set, get_builder_pubkey_from_state,
};
use tracing::debug;
use types::{
    BeaconState, ChainSpec, EthSpec, ExecutionPayloadBid, SignedExecutionPayloadBid,
    SignedProposerPreferences, Slot, consts::gloas::PAYLOAD_BUILDER_VERSION,
};

/// Verify that an execution payload bid is consistent with the current chain state
/// and proposer preferences.
///
/// These checks are shared by gossip and direct bids. Source-specific checks (e.g. the gossip-only
/// requirement that `execution_payment == 0`) are applied by the caller.
pub(crate) fn verify_bid_consistency<E: EthSpec>(
    bid: &ExecutionPayloadBid<E>,
    current_slot: Slot,
    proposer_preferences: &SignedProposerPreferences,
    head_state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), PayloadBidError> {
    let bid_slot = bid.slot;

    if bid_slot != current_slot && bid_slot != current_slot.saturating_add(1u64) {
        return Err(PayloadBidError::InvalidBidSlot { bid_slot });
    }

    if bid.fee_recipient != proposer_preferences.message.fee_recipient {
        return Err(PayloadBidError::InvalidFeeRecipient);
    }

    let max_blobs_per_block =
        spec.max_blobs_per_block(bid_slot.epoch(E::slots_per_epoch())) as usize;

    if bid.blob_kzg_commitments.len() > max_blobs_per_block {
        return Err(PayloadBidError::InvalidBlobKzgCommitments {
            max_blobs_per_block,
            blob_kzg_commitments_len: bid.blob_kzg_commitments.len(),
        });
    }

    verify_bid_state_conditions(bid, head_state, spec)
}

/// Verify the bid conditions that depend on the beacon `state`: the builder is active, is a payload
/// builder, and can cover the bid. These are exactly the state-dependent checks
/// `process_execution_payload_bid` re-applies in `per_block_processing`, and the only bid conditions
/// that can go stale between gossip verification and block production (e.g. the builder's balance
/// dropping). Re-running them against the production state lets bid selection drop a gossip bid that
/// has since become invalid, rather than committing to it and failing the whole block.
pub(crate) fn verify_bid_state_conditions<E: EthSpec>(
    bid: &ExecutionPayloadBid<E>,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), PayloadBidError> {
    let builder_index = bid.builder_index;

    let is_active_builder = state
        .is_active_builder(builder_index, spec)
        .map_err(|_| PayloadBidError::InvalidBuilder { builder_index })?;

    if !is_active_builder {
        return Err(PayloadBidError::InvalidBuilder { builder_index });
    }

    let builder_version = state.get_builder(builder_index)?.version;
    if builder_version != PAYLOAD_BUILDER_VERSION {
        return Err(PayloadBidError::InvalidBuilderVersion {
            builder_index,
            version: builder_version,
        });
    }

    if !state.can_builder_cover_bid(builder_index, bid.value, spec)? {
        return Err(PayloadBidError::BuilderCantCoverBid {
            builder_index,
            builder_bid: bid.value,
        });
    }

    Ok(())
}

/// Checks if `bid` is compatible with the head branch
pub(crate) fn is_bid_compatible_with_head<T: BeaconChainTypes>(
    cached_head: &CachedHead<T::EthSpec>,
    fork_choice_read: &ForkChoiceReadGuard<'_, T>,
    bid: &ExecutionPayloadBid<T::EthSpec>,
    spec: &ChainSpec,
) -> Result<bool, PayloadBidError> {
    let head_block_root = cached_head.head_block_root();

    let head_block = fork_choice_read
        .get_block(&head_block_root)
        .ok_or_else(|| {
            PayloadBidError::InternalError(format!(
                "head block {head_block_root:?} not found in fork choice"
            ))
        })?;

    // TODO(post-gloas) this can be removed after the gloas fork
    let head_is_pre_gloas = !spec
        .fork_name_at_slot::<T::EthSpec>(head_block.slot)
        .gloas_enabled();

    let (head_bid_parent_block_hash, head_bid_block_hash) = if head_is_pre_gloas {
        let parent_payload_hash = head_block
            .parent_root
            .and_then(|parent_root| fork_choice_read.get_block(&parent_root))
            .and_then(|parent| parent.execution_status.block_hash());
        (
            parent_payload_hash,
            head_block.execution_status.block_hash(),
        )
    } else {
        (
            head_block.execution_payload_parent_hash,
            head_block.execution_payload_block_hash,
        )
    };

    let builds_on_parent_block = Some(bid.parent_block_root) == head_block.parent_root;
    let builds_on_parent_payload = Some(bid.parent_block_hash) == head_bid_parent_block_hash;

    if builds_on_parent_block && builds_on_parent_payload {
        return Ok(true);
    }

    if bid.parent_block_root != head_block.root {
        return Ok(false);
    }

    let builds_on_head_payload = Some(bid.parent_block_hash) == head_bid_block_hash;

    if head_is_pre_gloas {
        return Ok(builds_on_head_payload);
    }

    if fork_choice_read
        .should_build_on_full(
            &head_block_root,
            cached_head.head_payload_status(),
            bid.slot,
        )
        .map_err(|e| {
            PayloadBidError::InternalError(format!("should_build_on_full failed: {e:?}"))
        })?
    {
        return Ok(builds_on_head_payload);
    }

    Ok(builds_on_parent_payload)
}

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub gossip_verified_payload_bid_cache: &'a GossipVerifiedPayloadBidCache<T::EthSpec>,
    pub gossip_verified_proposer_preferences_cache: &'a GossipVerifiedProposerPreferenceCache,
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
    pub store: &'a BeaconStore<T>,
}

/// A wrapper around a `SignedExecutionPayloadBid` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Educe)]
#[educe(Debug(bound = "E: EthSpec"), Clone(bound = "E: EthSpec"))]
pub struct GossipVerifiedPayloadBid<E: EthSpec> {
    pub signed_bid: Arc<SignedExecutionPayloadBid<E>>,
}

impl<E: EthSpec> GossipVerifiedPayloadBid<E> {
    pub fn new<T>(
        signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, PayloadBidError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        let bid_slot = signed_bid.message.slot;
        let bid_parent = BidParent::from_bid(&signed_bid.message);
        let bid_parent_block_root = signed_bid.message.parent_block_root;
        let bid_value = signed_bid.message.value;

        // Execution payments are used by off-protocol builders. In-protocol (gossip) bids should
        // always have this value set to zero.
        if signed_bid.message.execution_payment != 0 {
            return Err(PayloadBidError::ExecutionPaymentNonZero {
                execution_payment: signed_bid.message.execution_payment,
            });
        }

        if ctx
            .gossip_verified_payload_bid_cache
            .seen_builder_bid_for_parent(&bid_slot, bid_parent, signed_bid.message.builder_index)
        {
            return Err(PayloadBidError::BuilderAlreadySeen {
                builder_index: signed_bid.message.builder_index,
                slot: bid_slot,
            });
        }

        // TODO(gloas): Extract into `bid_value_over_threshold` on the bid cache and potentially
        // make this more sophisticate than just a <= check.
        if let Some(cached_bid) = ctx
            .gossip_verified_payload_bid_cache
            .get_highest_bid(bid_slot, bid_parent)
            && bid_value <= cached_bid.message.value
        {
            return Err(PayloadBidError::BidValueBelowCached {
                cached_value: cached_bid.message.value,
                incoming_value: bid_value,
            });
        }

        let cached_head = ctx.canonical_head.cached_head();
        let current_slot = ctx
            .slot_clock
            .now()
            .ok_or(PayloadBidError::UnableToReadSlot)?;
        let snapshot_state = &cached_head.snapshot.beacon_state;

        // At the Gloas fork boundary the head snapshot is still a pre-Gloas state, so we must
        // use the advanced state instead.
        // TODO(post-gloas) this can be removed after the gloas fork
        let advanced_state;
        let head_state = if ctx
            .spec
            .fork_name_at_slot::<T::EthSpec>(bid_slot)
            .gloas_enabled()
            && !snapshot_state.fork_name_unchecked().gloas_enabled()
        {
            let (_, state) = ctx
                .store
                .get_advanced_hot_state(
                    cached_head.head_block_root(),
                    bid_slot,
                    cached_head.head_state_root(),
                )
                .map_err(|e| {
                    PayloadBidError::InternalError(format!(
                        "failed to load advanced head state: {e:?}"
                    ))
                })?
                .ok_or_else(|| {
                    PayloadBidError::InternalError("advanced head state unavailable".to_string())
                })?;
            if !state.fork_name_unchecked().gloas_enabled() {
                return Err(PayloadBidError::InternalError(
                    "head state not yet advanced to Gloas".to_string(),
                ));
            }
            advanced_state = state;
            &advanced_state
        } else {
            snapshot_state
        };

        // Look up the preferences keyed by the dependent root that is canonical from our head's
        // perspective, so we don't pick up preferences cached for a competing branch's proposer.
        let proposal_epoch = bid_slot.epoch(T::EthSpec::slots_per_epoch());
        let dependent_root = head_state.proposer_shuffling_decision_root_at_epoch(
            proposal_epoch,
            cached_head.head_block_root(),
            ctx.spec,
        )?;

        let Some(proposer_preferences) = ctx
            .gossip_verified_proposer_preferences_cache
            .get_preferences(&bid_slot, dependent_root)
        else {
            return Err(PayloadBidError::NoProposerPreferences { slot: bid_slot });
        };

        let fork_choice = ctx.canonical_head.fork_choice_read_lock();

        // TODO(gloas) reprocess bids whose parent_block_root becomes known & canonical after a reorg?
        let parent_block = fork_choice.get_block(&bid_parent_block_root).ok_or(
            PayloadBidError::ParentBlockRootUnknown {
                parent_block_root: bid_parent_block_root,
            },
        )?;

        // [REJECT] The bid is for a higher slot than its parent block.
        if bid_slot <= parent_block.slot {
            return Err(PayloadBidError::BidNotDescendantOfParent {
                bid_slot,
                parent_slot: parent_block.slot,
            });
        }

        // [REJECT] `bid.prev_randao` is the correct RANDAO mix -- i.e. validate that
        // `bid.prev_randao == get_randao_mix(parent_state, get_current_epoch(parent_state))`.
        // Query the mix at the state's own current epoch (`head_state` stands in for the parent
        // post-state); using the wall-clock epoch instead would be out of bounds during the first
        // slot(s) of an epoch, before a block advances the head into it.
        if signed_bid.message.prev_randao
            != *head_state.get_randao_mix(head_state.current_epoch())?
        {
            return Err(PayloadBidError::InvalidPrevRandao { slot: bid_slot });
        }

        // TODO(gloas) should we reprocess a dropped bid when the head changes to its parent?
        if !is_bid_compatible_with_head(&cached_head, &fork_choice, &signed_bid.message, ctx.spec)?
        {
            return Err(PayloadBidError::BidNotCompatibleWithHead {
                parent_block_root: bid_parent_block_root,
            });
        }

        // TODO(gloas): [IGNORE] bid.parent_block_hash is the block hash of a known execution
        // payload in fork choice.

        // TODO(gloas): This uses head state's bid gas_limit as parent_gas_limit, which is only
        // correct when the bid's parent is the head. If the parent is an ancestor further back
        // this check may be inaccurate. Fixing this requires storing
        // gas_limit in fork choice or looking it up from the store by parent_block_hash. Taking the above
        // TODO into consideration maybe should persist parent block hash and gas limit in fork choice?
        if let Ok(parent_bid) = head_state.latest_execution_payload_bid()
            && !is_gas_limit_target_compatible(
                parent_bid.gas_limit,
                signed_bid.message.gas_limit,
                proposer_preferences.message.target_gas_limit,
            )?
        {
            return Err(PayloadBidError::InvalidGasLimit);
        }

        drop(fork_choice);

        verify_bid_consistency(
            &signed_bid.message,
            current_slot,
            &proposer_preferences,
            head_state,
            ctx.spec,
        )?;

        // Verify signature
        execution_payload_bid_signature_set(
            head_state,
            |i| get_builder_pubkey_from_state(head_state, i),
            &signed_bid,
            ctx.spec,
        )
        .map_err(|_| PayloadBidError::BadSignature)?
        .ok_or(PayloadBidError::BadSignature)?
        .verify()
        .then_some(())
        .ok_or(PayloadBidError::BadSignature)?;

        let gossip_verified_bid = GossipVerifiedPayloadBid { signed_bid };

        ctx.gossip_verified_payload_bid_cache
            .observe_bid(gossip_verified_bid.clone());

        Ok(gossip_verified_bid)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Build a `GossipVerificationContext` from this `BeaconChain` for `GossipVerifiedPayloadBid`.
    pub fn payload_bid_gossip_verification_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            gossip_verified_payload_bid_cache: &self.gossip_verified_payload_bid_cache,
            gossip_verified_proposer_preferences_cache: &self
                .gossip_verified_proposer_preferences_cache,
            slot_clock: &self.slot_clock,
            spec: &self.spec,
            store: &self.store,
        }
    }

    /// Returns `Ok(GossipVerifiedPayloadBid)` if the supplied `bid` should be forwarded onto the
    /// gossip network and cached.
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given bid was invalid, or an error was encountered during verification.
    pub fn verify_payload_bid_for_gossip(
        &self,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    ) -> Result<GossipVerifiedPayloadBid<T::EthSpec>, PayloadBidError> {
        let slot = bid.message.slot;
        let parent_block_root = bid.message.parent_block_root;
        let parent_block_hash = bid.message.parent_block_hash;

        let ctx = self.payload_bid_gossip_verification_context();
        match GossipVerifiedPayloadBid::new(bid, &ctx) {
            Ok(verified) => {
                debug!(
                    %slot,
                    %parent_block_hash,
                    %parent_block_root,
                    "Successfully verified gossip payload bid"
                );

                if let Some(event_handler) = self.event_handler.as_ref()
                    && event_handler.has_execution_payload_bid_subscribers()
                {
                    event_handler.register(EventKind::ExecutionPayloadBid(Box::new(
                        ForkVersionedResponse {
                            version: self.spec.fork_name_at_slot::<T::EthSpec>(slot),
                            metadata: Default::default(),
                            data: (*verified.signed_bid).clone(),
                        },
                    )));
                }

                Ok(verified)
            }
            Err(e) => {
                debug!(
                    error = e.to_string(),
                    %slot,
                    %parent_block_hash,
                    %parent_block_root,
                    "Rejected gossip payload bid"
                );
                Err(e)
            }
        }
    }
}

/// Check if `gas_limit` is compatible with `target_gas_limit` under the
/// EIP-1559 transition rule from `parent_gas_limit`.
pub fn is_gas_limit_target_compatible(
    parent_gas_limit: u64,
    gas_limit: u64,
    target_gas_limit: u64,
) -> Result<bool, PayloadBidError> {
    let max_gas_limit_difference = (parent_gas_limit / 1024)
        .max(1)
        .checked_sub(1)
        .ok_or(PayloadBidError::InvalidGasLimit)?;
    let min_gas_limit = parent_gas_limit
        .checked_sub(max_gas_limit_difference)
        .ok_or(PayloadBidError::InvalidGasLimit)?;
    let max_gas_limit = parent_gas_limit
        .checked_add(max_gas_limit_difference)
        .ok_or(PayloadBidError::InvalidGasLimit)?;

    if target_gas_limit >= min_gas_limit && target_gas_limit <= max_gas_limit {
        Ok(gas_limit == target_gas_limit)
    } else if target_gas_limit > max_gas_limit {
        Ok(gas_limit == max_gas_limit)
    } else {
        Ok(gas_limit == min_gas_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::is_gas_limit_target_compatible;
    use bls::Signature;
    use kzg::KzgCommitment;
    use ssz_types::ProgressiveVariableList;
    use types::{
        Address, BeaconState, ChainSpec, EthSpec, ExecutionPayloadBid, MinimalEthSpec,
        ProposerPreferences, SignedProposerPreferences, Slot,
    };

    use super::verify_bid_consistency;
    use crate::payload_bid_verification::PayloadBidError;

    type E = MinimalEthSpec;

    fn make_bid(slot: Slot, fee_recipient: Address, gas_limit: u64) -> ExecutionPayloadBid<E> {
        ExecutionPayloadBid {
            slot,
            fee_recipient,
            gas_limit,
            value: 100,
            ..ExecutionPayloadBid::default()
        }
    }

    fn make_preferences(
        fee_recipient: Address,
        target_gas_limit: u64,
    ) -> SignedProposerPreferences {
        SignedProposerPreferences {
            message: ProposerPreferences {
                fee_recipient,
                target_gas_limit,
                ..ProposerPreferences::default()
            },
            signature: Signature::empty(),
        }
    }

    fn state_and_spec() -> (BeaconState<E>, ChainSpec) {
        let spec = E::default_spec();
        let state = BeaconState::new(0, <_>::default(), &spec);
        (state, spec)
    }

    #[test]
    fn test_invalid_bid_slot_too_old() {
        let (state, spec) = state_and_spec();
        let current_slot = Slot::new(10);
        let bid = make_bid(Slot::new(5), Address::ZERO, 30_000_000);
        let prefs = make_preferences(Address::ZERO, 30_000_000);

        let result = verify_bid_consistency::<E>(&bid, current_slot, &prefs, &state, &spec);
        assert!(matches!(
            result,
            Err(PayloadBidError::InvalidBidSlot { .. })
        ));
    }

    #[test]
    fn test_invalid_bid_slot_too_far_ahead() {
        let (state, spec) = state_and_spec();
        let current_slot = Slot::new(10);
        let bid = make_bid(Slot::new(12), Address::ZERO, 30_000_000);
        let prefs = make_preferences(Address::ZERO, 30_000_000);

        let result = verify_bid_consistency::<E>(&bid, current_slot, &prefs, &state, &spec);
        assert!(matches!(
            result,
            Err(PayloadBidError::InvalidBidSlot { .. })
        ));
    }

    #[test]
    fn test_fee_recipient_mismatch() {
        let (state, spec) = state_and_spec();
        let current_slot = Slot::new(10);
        let bid = make_bid(current_slot, Address::ZERO, 30_000_000);
        let prefs = make_preferences(Address::repeat_byte(0xaa), 30_000_000);

        let result = verify_bid_consistency::<E>(&bid, current_slot, &prefs, &state, &spec);
        assert!(matches!(result, Err(PayloadBidError::InvalidFeeRecipient)));
    }

    #[test]
    fn test_invalid_blob_kzg_commitments() {
        let (state, spec) = state_and_spec();
        let current_slot = Slot::new(10);
        let mut bid = make_bid(current_slot, Address::ZERO, 30_000_000);
        let prefs = make_preferences(Address::ZERO, 30_000_000);

        let max_blobs = spec.max_blobs_per_block(current_slot.epoch(E::slots_per_epoch())) as usize;
        let commitments: Vec<KzgCommitment> = (0..=max_blobs)
            .map(|_| KzgCommitment::empty_for_testing())
            .collect();
        bid.blob_kzg_commitments = ProgressiveVariableList::new(commitments);

        let result = verify_bid_consistency::<E>(&bid, current_slot, &prefs, &state, &spec);
        assert!(matches!(
            result,
            Err(PayloadBidError::InvalidBlobKzgCommitments { .. })
        ));
    }

    #[test]
    fn test_is_gas_limit_target_compatible_increase_within_limit() {
        assert!(is_gas_limit_target_compatible(60_000_000, 60_000_100, 60_000_100).unwrap());
    }

    #[test]
    fn test_is_gas_limit_target_compatible_increase_exceeding_limit() {
        // max_diff = 60_000_000 / 1024 - 1 = 58_592
        // max_gas_limit = 60_000_000 + 58_592 = 60_058_592
        assert!(is_gas_limit_target_compatible(60_000_000, 60_058_592, 100_000_000).unwrap());
    }

    #[test]
    fn test_is_gas_limit_target_compatible_increase_exceeding_off_by_one() {
        assert!(!is_gas_limit_target_compatible(60_000_000, 60_058_593, 100_000_000).unwrap());
    }

    #[test]
    fn test_is_gas_limit_target_compatible_decrease_within_limit() {
        assert!(is_gas_limit_target_compatible(60_000_000, 59_999_990, 59_999_990).unwrap());
    }

    #[test]
    fn test_is_gas_limit_target_compatible_decrease_exceeding_limit() {
        // min_gas_limit = 60_000_000 - 58_592 = 59_941_408
        assert!(is_gas_limit_target_compatible(60_000_000, 59_941_408, 30_000_000).unwrap());
    }

    #[test]
    fn test_is_gas_limit_target_compatible_target_equals_parent() {
        assert!(is_gas_limit_target_compatible(60_000_000, 60_000_000, 60_000_000).unwrap());
    }

    #[test]
    fn test_is_gas_limit_target_compatible_parent_underflows() {
        // parent=1023: max(1023/1024, 1) - 1 = max(0, 1) - 1 = 0, no change allowed
        assert!(is_gas_limit_target_compatible(1023, 1023, 60_000_000).unwrap());
    }
}
