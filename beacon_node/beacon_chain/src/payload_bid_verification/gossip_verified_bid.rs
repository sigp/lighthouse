use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BeaconStore, CanonicalHead,
    payload_bid_verification::{PayloadBidError, payload_bid_cache::GossipVerifiedPayloadBidCache},
    proposer_preferences_verification::proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
};
use educe::Educe;
use state_processing::signature_sets::{
    execution_payload_bid_signature_set, get_builder_pubkey_from_state,
};
use tracing::{Span, debug};
use types::{BeaconState, ChainSpec, SignedExecutionPayloadBid};

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub gossip_verified_payload_bid_cache: &'a GossipVerifiedPayloadBidCache<T>,
    pub gossip_verified_proposer_preferences_cache: &'a GossipVerifiedProposerPreferenceCache,
    pub store: &'a BeaconStore<T>,
    pub spec: &'a ChainSpec,
}

/// A wrapper around a `SignedExecutionPayloadBid` that indicates that it's signature has been verified.
#[derive(Educe)]
#[educe(
    Debug(bound = "T: BeaconChainTypes"),
    Clone(bound = "T: BeaconChainTypes")
)]

pub struct SignatureVerifiedPayloadBid<T: BeaconChainTypes> {
    pub signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
}

impl<T: BeaconChainTypes> SignatureVerifiedPayloadBid<T> {
    pub fn new(
        signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        state: &BeaconState<T::EthSpec>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, PayloadBidError> {
        execution_payload_bid_signature_set(
            state,
            |i| get_builder_pubkey_from_state(state, i),
            &signed_bid,
            &ctx.spec,
        )
        .map_err(|_| PayloadBidError::BadSignature)?
        .ok_or(PayloadBidError::BadSignature)?
        .verify()
        .then_some(())
        .ok_or(PayloadBidError::BadSignature)?;

        let signature_verified_bid = Self { signed_bid };

        Ok(signature_verified_bid)
    }
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

impl<T: BeaconChainTypes> From<SignatureVerifiedPayloadBid<T>> for GossipVerifiedPayloadBid<T> {
    fn from(bid: SignatureVerifiedPayloadBid<T>) -> Self {
        Self {
            signed_bid: bid.signed_bid,
        }
    }
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
        let builder_index = signed_bid.message.builder_index;

        if ctx
            .gossip_verified_payload_bid_cache
            .seen_builder_index(&bid_slot, signed_bid.message.builder_index)
        {
            return Err(PayloadBidError::BuilderAlreadySeen {
                builder_index: signed_bid.message.builder_index,
                slot: bid_slot,
            });
        }

         if let Some(cached_bid) = ctx.gossip_verified_payload_bid_cache.get_highest_bid(
            bid_slot,
            bid_parent_block_hash,
            bid_parent_block_root,
        ) {
            if bid_value <= cached_bid.message.value {
                return Err(PayloadBidError::BidValueBelowCached {
                    cached_value: cached_bid.message.value,
                    incoming_value: bid_value,
                });
            }
        }

        let current_slot = ctx.canonical_head.cached_head().head_slot();

        if bid_slot != current_slot && bid_slot != current_slot + 1 {
            return Err(PayloadBidError::InvalidBidSlot { bid_slot });
        }

        if signed_bid.message.execution_payment != 0 {
            return Err(PayloadBidError::ExecutionPaymentNonZero {
                execution_payment: signed_bid.message.execution_payment,
            });
        }

        if let Some(proposer_preferences) = ctx
            .gossip_verified_proposer_preferences_cache
            .get_preferences(&bid_slot)
        {
            if signed_bid.message.fee_recipient != proposer_preferences.message.fee_recipient {
                return Err(PayloadBidError::InvalidFeeRecipient);
            }
            if signed_bid.message.gas_limit != proposer_preferences.message.gas_limit {
                return Err(PayloadBidError::InvalidGasLimit);
            }
        } else {
            return Err(PayloadBidError::NoProposerPreferences { slot: bid_slot });
        }

        let fork_choice = ctx.canonical_head.fork_choice_read_lock();

        if !fork_choice.contains_block(&bid_parent_block_root) {
            return Err(PayloadBidError::ParentBlockRootUnknown {
                parent_block_root: bid_parent_block_root,
            });
        }

        // TODO(gloas) [IGNORE] bid.parent_block_hash is the block hash of a known execution payload in fork choice.

        drop(fork_choice);

        let head_state = &ctx.canonical_head.cached_head().snapshot.beacon_state;

        if !head_state.is_active_builder(builder_index, &ctx.spec)? {
            return Err(PayloadBidError::InvalidBuilder { builder_index });
        }

        if !head_state.can_builder_cover_bid(builder_index, bid_value, &ctx.spec)? {
            return Err(PayloadBidError::BuilderCantCoverBid {
                builder_index,
                builder_bid: bid_value,
            });
        }

        let signature_verified_bid =
            SignatureVerifiedPayloadBid::new(signed_bid.clone(), head_state, ctx)?;

        ctx.gossip_verified_payload_bid_cache
            .insert_seen_builder(signature_verified_bid.clone());
       
        let gossip_verified_bid: GossipVerifiedPayloadBid<T> = signature_verified_bid.into();

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
            store: &self.store,
            gossip_verified_payload_bid_cache: &self.gossip_verified_payload_bid_cache,
            gossip_verified_proposer_preferences_cache: &self
                .gossip_verified_proposer_preferences_cache,
            spec: &self.spec,
        }
    }

    /// Returns `Ok(GossipVerifiedPayloadBid)` if the supplied `bid` should be forwarded onto the
    /// gossip network and cached.
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given bid was invalid, or an error was encountered during verification.
    pub async fn verify_payload_bid_for_gossip(
        self: &Arc<Self>,
        bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    ) -> Result<GossipVerifiedPayloadBid<T>, PayloadBidError> {
        let chain = self.clone();
        let span = Span::current();
        self.task_executor
            .clone()
            .spawn_blocking_handle(
                move || {
                    let _guard = span.enter();
                    let slot = bid.message.slot;
                    let parent_block_root = bid.message.parent_block_root;
                    let parent_block_hash = bid.message.parent_block_hash;

                    let ctx = chain.payload_bid_gossip_verification_context();
                    match GossipVerifiedPayloadBid::new(bid, &ctx) {
                        Ok(verified) => {
                            debug!(
                                %slot,
                                %parent_block_hash,
                                %parent_block_root,
                                "Successfully verified gossip payload bid"
                            );

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
                },
                "gossip_envelope_verification_handle",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?
            .await
            .map_err(BeaconChainError::TokioJoin)?
    }
}
