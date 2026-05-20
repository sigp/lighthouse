use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainTypes, CanonicalHead,
    payload_bid_verification::{PayloadBidError, payload_bid_cache::GossipVerifiedPayloadBidCache},
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
    SignedProposerPreferences, Slot,
};

/// Verify that an execution payload bid is consistent with the current chain state
/// and proposer preferences.
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

    // Execution payments are used by off protocol builders. In protocol bids
    // should always have this value set to zero.
    if bid.execution_payment != 0 {
        return Err(PayloadBidError::ExecutionPaymentNonZero {
            execution_payment: bid.execution_payment,
        });
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

    let builder_index = bid.builder_index;

    let is_active_builder = head_state
        .is_active_builder(builder_index, spec)
        .map_err(|_| PayloadBidError::InvalidBuilder { builder_index })?;

    if !is_active_builder {
        return Err(PayloadBidError::InvalidBuilder { builder_index });
    }

    if !head_state.can_builder_cover_bid(builder_index, bid.value, spec)? {
        return Err(PayloadBidError::BuilderCantCoverBid {
            builder_index,
            builder_bid: bid.value,
        });
    }

    Ok(())
}

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub gossip_verified_payload_bid_cache: &'a GossipVerifiedPayloadBidCache<T>,
    pub gossip_verified_proposer_preferences_cache: &'a GossipVerifiedProposerPreferenceCache,
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
}

/// A wrapper around a `SignedExecutionPayloadBid` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Educe)]
#[educe(
    Debug(bound = "T: BeaconChainTypes"),
    Clone(bound = "T: BeaconChainTypes")
)]
pub struct GossipVerifiedPayloadBid<T: BeaconChainTypes> {
    pub signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
}

impl<T: BeaconChainTypes> GossipVerifiedPayloadBid<T> {
    pub fn new(
        signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, PayloadBidError> {
        let bid_slot = signed_bid.message.slot;
        let bid_parent_block_hash = signed_bid.message.parent_block_hash;
        let bid_parent_block_root = signed_bid.message.parent_block_root;
        let bid_value = signed_bid.message.value;

        if ctx
            .gossip_verified_payload_bid_cache
            .seen_builder_index(&bid_slot, signed_bid.message.builder_index)
        {
            return Err(PayloadBidError::BuilderAlreadySeen {
                builder_index: signed_bid.message.builder_index,
                slot: bid_slot,
            });
        }

        // TODO(gloas): Extract into `bid_value_over_threshold` on the bid cache and potentially
        // make this more sophisticate than just a <= check.
        if let Some(cached_bid) = ctx.gossip_verified_payload_bid_cache.get_highest_bid(
            bid_slot,
            bid_parent_block_hash,
            bid_parent_block_root,
        ) && bid_value <= cached_bid.message.value
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
        let head_state = &cached_head.snapshot.beacon_state;

        let Some(proposer_preferences) = ctx
            .gossip_verified_proposer_preferences_cache
            .get_preferences(&bid_slot)
        else {
            return Err(PayloadBidError::NoProposerPreferences { slot: bid_slot });
        };

        let fork_choice = ctx.canonical_head.fork_choice_read_lock();

        // TODO(gloas) reprocess bids whose parent_block_root becomes known & canonical after a reorg?
        if !fork_choice.contains_block(&bid_parent_block_root) {
            return Err(PayloadBidError::ParentBlockRootUnknown {
                parent_block_root: bid_parent_block_root,
            });
        }

        // TODO(gloas) reprocess bids whose parent_block_root becomes canonical after a reorg.
        let head_root = cached_head.head_block_root();
        if !fork_choice.is_descendant(bid_parent_block_root, head_root) {
            return Err(PayloadBidError::ParentBlockRootNotCanonical {
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
            .insert_seen_builder(&gossip_verified_bid);

        ctx.gossip_verified_payload_bid_cache
            .insert_highest_bid(gossip_verified_bid.clone());

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
    ) -> Result<GossipVerifiedPayloadBid<T>, PayloadBidError> {
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
    use ssz_types::VariableList;
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
    fn test_execution_payment_nonzero() {
        let (state, spec) = state_and_spec();
        let current_slot = Slot::new(10);
        let mut bid = make_bid(current_slot, Address::ZERO, 30_000_000);
        bid.execution_payment = 42;
        let prefs = make_preferences(Address::ZERO, 30_000_000);

        let result = verify_bid_consistency::<E>(&bid, current_slot, &prefs, &state, &spec);
        assert!(matches!(
            result,
            Err(PayloadBidError::ExecutionPaymentNonZero {
                execution_payment: 42
            })
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
        bid.blob_kzg_commitments = VariableList::new(commitments).unwrap();

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
