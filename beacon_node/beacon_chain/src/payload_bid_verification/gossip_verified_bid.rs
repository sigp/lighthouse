use std::sync::Arc;

use crate::{BeaconChain, BeaconChainTypes, payload_bid_verification::PayloadBidError};
use educe::Educe;
use state_processing::signature_sets::{
    execution_payload_bid_signature_set, get_builder_pubkey_from_state,
};
use types::{SignedExecutionPayloadBid, Slot};

/// A wrapper around a `SignedExecutionPayloadBid` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Educe)]
#[educe(Debug(bound = "T: BeaconChainTypes"))]
pub struct GossipVerifiedPayloadBid<T: BeaconChainTypes> {
    pub signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
}

impl<T: BeaconChainTypes> GossipVerifiedPayloadBid<T> {
    pub fn new(
        signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
        chain: Arc<BeaconChain<T>>,
    ) -> Result<Self, PayloadBidError> {
        let bid_slot = signed_bid.message.slot;
        let bid_parent_block_hash = signed_bid.message.parent_block_hash;
        let bid_parent_block_root = signed_bid.message.parent_block_root;
        let bid_value = signed_bid.message.value;
        let builder_index = signed_bid.message.builder_index;

        if let Some(cached_bid) = chain.gossip_verified_payload_bid_cache.get_highest_bid(
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

        let current_slot = chain.canonical_head.cached_head().head_slot();

        if bid_slot != current_slot && bid_slot != current_slot + 1 {
            return Err(PayloadBidError::InvalidBidSlot { bid_slot });
        }

        if signed_bid.message.execution_payment != 0 {
            return Err(PayloadBidError::ExecutionPaymentNonZero {
                execution_payment: signed_bid.message.execution_payment,
            });
        }

        if let Some(proposer_preferences) = chain
            .gossip_verified_proposer_preferences_cache
            .get(&bid_slot)
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

        if chain
            .gossip_verified_payload_bid_cache
            .seen_builder_index(&bid_slot, signed_bid.message.builder_index)
        {
            return Err(PayloadBidError::BuilderAlreadySeen {
                builder_index: signed_bid.message.builder_index,
                slot: bid_slot,
            });
        }

        let fork_choice = chain.canonical_head.fork_choice_read_lock();

        if !fork_choice.contains_block(&bid_parent_block_root) {
            return Err(PayloadBidError::ParentBlockRootUnknown {
                parent_block_root: bid_parent_block_root,
            });
        }

        // [IGNORE] bid.parent_block_hash is the block hash of a known execution payload in fork choice.

        let head_state = &chain.canonical_head.cached_head().snapshot.beacon_state;

        if !head_state.is_active_builder(builder_index, &chain.spec)? {
            return Err(PayloadBidError::InvalidBuilder { builder_index });
        }

        if !head_state.can_builder_cover_bid(builder_index, bid_value, &chain.spec)? {
            return Err(PayloadBidError::BuilderCantCoverBid {
                builder_index,
                builder_bid: bid_value,
            });
        }

        execution_payload_bid_signature_set(
            head_state,
            |i| get_builder_pubkey_from_state(head_state, i),
            &signed_bid,
            &chain.spec,
        )
        .map_err(|_| PayloadBidError::BadSignature)?
        .ok_or(PayloadBidError::BadSignature)?
        .verify()
        .then_some(())
        .ok_or(PayloadBidError::BadSignature)?;

        Ok(Self { signed_bid })
    }
}
