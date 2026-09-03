use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainTypes, BeaconStore, CachedHead, CanonicalHead,
    canonical_head::ForkChoiceReadGuard,
    observed_execution_payloads::ObservedExecutionPayloads,
    payload_bid_verification::{
        PayloadBidError,
        payload_bid_cache::{BidParent, GossipVerifiedPayloadBidCache},
    },
    proposer_preferences_verification::proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
};
use educe::Educe;
use eth2::types::{EventKind, ForkVersionedResponse};
use slot_clock::SlotClock;
use state_processing::{
    builder_deposits_cache::OnboardBuildersCache,
    signature_sets::{execution_payload_bid_signature_set, get_builder_pubkey_from_state},
    state_advance::complete_state_advance,
};
use tracing::debug;
use types::{
    BeaconState, ChainSpec, EthSpec, ExecutionPayloadBid, SignedExecutionPayloadBid, Slot,
    consts::gloas::PAYLOAD_BUILDER_VERSION,
};

fn verify_bid_payment_and_blobs<E: EthSpec>(
    bid: &ExecutionPayloadBid<E>,
    spec: &ChainSpec,
) -> Result<(), PayloadBidError> {
    let bid_slot = bid.slot;

    // Execution payments are used by off protocol builders. In protocol bids
    // should always have this value set to zero.
    if bid.execution_payment != 0 {
        return Err(PayloadBidError::ExecutionPaymentNonZero {
            execution_payment: bid.execution_payment,
        });
    }

    let max_blobs_per_block =
        spec.max_blobs_per_block(bid_slot.epoch(E::slots_per_epoch())) as usize;

    if bid.blob_kzg_commitments.len() > max_blobs_per_block {
        return Err(PayloadBidError::InvalidBlobKzgCommitments {
            max_blobs_per_block,
            blob_kzg_commitments_len: bid.blob_kzg_commitments.len(),
        });
    }

    Ok(())
}

fn verify_builder<E: EthSpec>(
    bid: &ExecutionPayloadBid<E>,
    bid_state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), PayloadBidError> {
    let builder_index = bid.builder_index;
    let builder_version = bid_state
        .get_builder(builder_index)
        .map_err(|_| PayloadBidError::InvalidBuilder { builder_index })?
        .version;

    if !bid_state.can_builder_cover_bid(builder_index, bid.value, spec)? {
        return Err(PayloadBidError::BuilderCantCoverBid {
            builder_index,
            builder_bid: bid.value,
        });
    }

    let is_active_builder = bid_state
        .is_active_builder(builder_index, spec)
        .map_err(|_| PayloadBidError::InvalidBuilder { builder_index })?;
    if !is_active_builder {
        return Err(PayloadBidError::InvalidBuilder { builder_index });
    }

    if builder_version != PAYLOAD_BUILDER_VERSION {
        return Err(PayloadBidError::InvalidBuilderVersion {
            builder_index,
            version: builder_version,
        });
    }

    Ok(())
}

fn verify_bid_slot_range<S: SlotClock>(
    slot_clock: &S,
    bid_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), PayloadBidError> {
    let current_time = slot_clock
        .now_duration()
        .ok_or(PayloadBidError::UnableToReadSlot)?;
    let earliest_permissible_time = slot_clock
        .start_of(bid_slot.saturating_sub(1u64))
        .ok_or(PayloadBidError::UnableToReadSlot)?
        .saturating_sub(spec.maximum_gossip_clock_disparity());
    let latest_permissible_time = slot_clock
        .start_of(bid_slot.saturating_add(1u64))
        .ok_or(PayloadBidError::UnableToReadSlot)?
        .saturating_add(spec.maximum_gossip_clock_disparity());

    if current_time < earliest_permissible_time {
        return Err(PayloadBidError::InvalidBidSlot { bid_slot });
    }

    if current_time > latest_permissible_time {
        return Err(PayloadBidError::InvalidBidSlot { bid_slot });
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
    pub builder_onboarding_cache: Option<&'a OnboardBuildersCache>,
    pub canonical_head: &'a CanonicalHead<T>,
    pub observed_execution_payloads: &'a ObservedExecutionPayloads,
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

        verify_bid_slot_range(ctx.slot_clock, bid_slot, ctx.spec)?;

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
        // make this more sophisticated than just a <= check.
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

        verify_bid_payment_and_blobs(&signed_bid.message, ctx.spec)?;

        // The spec evaluates the remaining state-dependent checks against the post-state of the
        // bid's parent block, which can be either the head or the head's parent.
        let fork_choice = ctx.canonical_head.fork_choice_read_lock();
        let parent_block = fork_choice.get_block(&bid_parent_block_root).ok_or(
            PayloadBidError::ParentBlockRootUnknown {
                parent_block_root: bid_parent_block_root,
            },
        )?;
        let parent_slot = parent_block.slot;
        let parent_state_root = parent_block.state_root;

        if bid_slot <= parent_slot {
            return Err(PayloadBidError::BidNotDescendantOfParent {
                bid_slot,
                parent_slot,
            });
        }
        drop(fork_choice);

        let parent_state = ctx
            .store
            .get_state(&parent_state_root, Some(parent_slot), true)
            .map_err(|e| {
                PayloadBidError::InternalError(format!(
                    "failed to load bid parent state {parent_state_root:?}: {e:?}"
                ))
            })?
            .ok_or(PayloadBidError::ParentBlockStateUnknown {
                parent_block_root: bid_parent_block_root,
                parent_state_root,
            })?;

        let proposal_epoch = bid_slot.epoch(T::EthSpec::slots_per_epoch());
        if proposal_epoch
            > parent_state
                .current_epoch()
                .saturating_add(ctx.spec.min_seed_lookahead)
        {
            return Err(PayloadBidError::BidOutsideParentProposerLookahead {
                bid_slot,
                parent_slot,
            });
        }

        // Key preferences by the dependent root derived from this bid's parent branch.
        let dependent_root = parent_state.proposer_shuffling_decision_root_at_epoch(
            proposal_epoch,
            bid_parent_block_root,
            ctx.spec,
        )?;

        let Some(proposer_preferences) = ctx
            .gossip_verified_proposer_preferences_cache
            .get_preferences(&bid_slot, dependent_root)
        else {
            return Err(PayloadBidError::NoProposerPreferences { slot: bid_slot });
        };

        if signed_bid.message.fee_recipient != proposer_preferences.message.fee_recipient {
            return Err(PayloadBidError::InvalidFeeRecipient);
        }

        let parent_gas_limit = ctx
            .observed_execution_payloads
            .get_gas_limit(signed_bid.message.parent_block_hash)
            .ok_or(PayloadBidError::ParentExecutionPayloadUnknown {
                parent_block_hash: signed_bid.message.parent_block_hash,
            })?;
        if !is_gas_limit_target_compatible(
            parent_gas_limit,
            signed_bid.message.gas_limit,
            proposer_preferences.message.target_gas_limit,
        )? {
            return Err(PayloadBidError::InvalidGasLimit);
        }

        let cached_head = ctx.canonical_head.cached_head();
        let fork_choice = ctx.canonical_head.fork_choice_read_lock();
        // TODO(gloas) should we reprocess a dropped bid when the head changes to its parent?
        if !is_bid_compatible_with_head(&cached_head, &fork_choice, &signed_bid.message, ctx.spec)?
        {
            return Err(PayloadBidError::BidNotCompatibleWithHead {
                parent_block_root: bid_parent_block_root,
            });
        }
        drop(fork_choice);

        // `prev_randao` is checked against the unadvanced parent post-state.
        if signed_bid.message.prev_randao
            != *parent_state.get_randao_mix(parent_state.current_epoch())?
        {
            return Err(PayloadBidError::InvalidPrevRandao { slot: bid_slot });
        }

        // Builder validity and balance are evaluated at the bid's slot, after applying any skipped
        // slot and epoch processing to the parent block post-state.
        let mut bid_state = parent_state.clone();
        complete_state_advance(
            &mut bid_state,
            Some(parent_state_root),
            bid_slot,
            ctx.builder_onboarding_cache,
            ctx.spec,
        )
        .map_err(|e| {
            PayloadBidError::InternalError(format!("failed to advance state to bid slot: {e:?}"))
        })?;
        if !bid_state.fork_name_unchecked().gloas_enabled() {
            return Err(PayloadBidError::InternalError(
                "bid state not yet advanced to Gloas".to_string(),
            ));
        }

        verify_builder(&signed_bid.message, &bid_state, ctx.spec)?;

        execution_payload_bid_signature_set(
            &bid_state,
            |i| get_builder_pubkey_from_state(&bid_state, i),
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
            .insert_seen_builder_bid(&gossip_verified_bid);

        ctx.gossip_verified_payload_bid_cache
            .insert_highest_bid(gossip_verified_bid.clone());

        Ok(gossip_verified_bid)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Build a `GossipVerificationContext` from this `BeaconChain` for `GossipVerifiedPayloadBid`.
    pub fn payload_bid_gossip_verification_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            builder_onboarding_cache: self.builder_onboarding_cache.as_deref(),
            canonical_head: &self.canonical_head,
            observed_execution_payloads: &self.observed_execution_payloads,
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
    use super::{is_gas_limit_target_compatible, verify_bid_slot_range};
    use std::time::Duration;
    use types::{EthSpec, MinimalEthSpec, Slot};

    use crate::payload_bid_verification::PayloadBidError;
    use crate::slot_clock::{SlotClock, TestingSlotClock};

    type E = MinimalEthSpec;

    #[test]
    fn test_bid_slot_upper_disparity_boundary() {
        let spec = E::default_spec();
        let slot_clock =
            TestingSlotClock::new(Slot::new(0), Duration::ZERO, spec.get_slot_duration());
        let bid_slot = Slot::new(100);
        let upper_boundary = slot_clock
            .start_of(bid_slot.saturating_add(1u64))
            .unwrap()
            .saturating_add(spec.maximum_gossip_clock_disparity());

        slot_clock.set_current_time(upper_boundary);
        assert!(verify_bid_slot_range(&slot_clock, bid_slot, &spec).is_ok());

        slot_clock.set_current_time(upper_boundary.saturating_add(Duration::from_millis(1)));
        assert!(matches!(
            verify_bid_slot_range(&slot_clock, bid_slot, &spec),
            Err(PayloadBidError::InvalidBidSlot { .. })
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
