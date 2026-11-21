use std::sync::Arc;

use crate::{
    BeaconChainTypes,
    payload_bid_verification::{
        PayloadBidError,
        gossip_verified_bid::{
            GossipVerificationContext, emit_best_execution_payload_bid, verify_bid_conditions,
            verify_bid_slot,
        },
    },
};
use eth2::types::BestExecutionPayloadBidSource;
use slot_clock::SlotClock;
use tracing::debug;
use types::SignedExecutionPayloadBid;

/// Verify a validator-fed bid (`POST validator/execution_payload_bids`) and, if valid, store it
/// for block production.
///
/// The checks are the same, in the same order, as [`GossipVerifiedPayloadBid::new`] minus its
/// gossip-only ones (the highest-value check, the one-bid-per-builder check and the zero
/// `execution_payment` rule), so a fed bid may carry a non-zero `execution_payment` or share its
/// slot/parent/builder with an earlier bid. The bid is stored apart from the gossip state, is
/// never published, and no `execution_payload_bid` event is emitted for it. A
/// `best_execution_payload_bid` event is emitted if it becomes the best bid for its parent.
///
/// [`GossipVerifiedPayloadBid::new`]: crate::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid::new
pub fn verify_validator_fed_bid<T: BeaconChainTypes>(
    signed_bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    ctx: &GossipVerificationContext<'_, T>,
) -> Result<(), PayloadBidError> {
    let slot = signed_bid.message().slot();
    let parent_block_root = signed_bid.message().parent_block_root();
    let parent_block_hash = signed_bid.message().parent_block_hash();

    let verification = (|| {
        // Ensure the bid is the correct structure for the fork at `bid.slot()`.
        signed_bid
            .fork_name(ctx.spec)
            .map_err(PayloadBidError::InconsistentFork)?;

        let current_slot = ctx
            .slot_clock
            .now()
            .ok_or(PayloadBidError::UnableToReadSlot)?;
        verify_bid_slot(slot, current_slot)?;

        verify_bid_conditions(&signed_bid, ctx)
    })();

    match verification {
        Ok(()) => {
            let beats_highest = ctx
                .gossip_verified_payload_bid_cache
                .beats_highest_gossip_or_fed_bid(&signed_bid);
            let is_inserted = ctx
                .gossip_verified_payload_bid_cache
                .insert_validator_fed_bid(signed_bid.clone());
            if beats_highest && is_inserted {
                emit_best_execution_payload_bid(
                    ctx.event_handler,
                    BestExecutionPayloadBidSource::Api,
                    &signed_bid,
                    ctx.spec,
                );
            }
            debug!(
                %slot,
                %parent_block_hash,
                %parent_block_root,
                is_inserted,
                "Successfully verified validator-fed payload bid"
            );
            Ok(())
        }
        Err(e) => {
            debug!(
                error = e.to_string(),
                %slot,
                %parent_block_hash,
                %parent_block_root,
                "Rejected validator-fed payload bid"
            );
            Err(e)
        }
    }
}
