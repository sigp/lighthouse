//! The incremental processing steps are represented as a sequence of wrapper-types around the bid.
//! There is a linear progression of types, starting at a `SignedExecutionPayloadBid` and finishing
//! with an `GossipVerifiedPayloadBid` which is then inserted into the `GossipVerifiedPayloadBidCache`
//!
//! ```ignore
//!    SignedExecutionPayloadBid
//!              |
//!              ▼
//!    SignatureVerifiedPayloadBid -------> Insert into GossipVerifiedPayloadBidCache::seen_builder
//!              |
//!              ▼
//!    GossipVerifiedPayloadBid -------> Insert into GossipVerifiedPayloadBidCache::highest_bid
//! ```

use std::sync::Arc;

use types::{BeaconStateError, Hash256, Slot};

use crate::BeaconChainError;

pub mod gossip_verified_bid;
pub mod payload_bid_cache;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum PayloadBidError {
    /// The bid's parent block root is unknown.
    ParentBlockRootUnknown { parent_block_root: Hash256 },
    /// The signature is invalid.
    BadSignature,
    /// A bid for this builder at this slot has already been seen.
    BuilderAlreadySeen { builder_index: u64, slot: Slot },
    /// Builder is not valid/active for the given epoch
    InvalidBuilder { builder_index: u64 },
    /// The bid value is lower than the currently cached bid.
    BidValueBelowCached {
        cached_value: u64,
        incoming_value: u64,
    },
    /// The bids slot is not the current slot or the next slot.
    InvalidBidSlot { bid_slot: Slot },
    /// No proposer preferences for the current slot.
    NoProposerPreferences { slot: Slot },
    /// The builder doesn't have enough deposited funds to cover the bid.
    BuilderCantCoverBid {
        builder_index: u64,
        builder_bid: u64,
    },
    /// The bids fee recipient doesn't match the proposer preferences fee recipient.
    InvalidFeeRecipient,
    /// The bids gas limit doesn't match the proposer preferences gas limit.
    InvalidGasLimit,
    /// The bids execution payment is non-zero
    ExecutionPaymentNonZero { execution_payment: u64 },
    /// Some Beacon Chain Error
    BeaconChainError(Arc<BeaconChainError>),
    /// Some Beacon State error
    BeaconStateError(BeaconStateError),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for PayloadBidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconStateError> for PayloadBidError {
    fn from(e: BeaconStateError) -> Self {
        PayloadBidError::BeaconStateError(e)
    }
}

impl From<BeaconChainError> for PayloadBidError {
    fn from(e: BeaconChainError) -> Self {
        PayloadBidError::BeaconChainError(Arc::new(e))
    }
}
