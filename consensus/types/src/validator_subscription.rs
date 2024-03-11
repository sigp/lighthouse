use crate::*;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// A validator subscription, created when a validator subscribes to a slot to perform optional aggregation
/// duties.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode, Eq, PartialOrd, Ord)]
pub struct ValidatorSubscription {
    /// The index of the committee within `slot` of which the validator is a member. Used by the
    /// beacon node to quickly evaluate the associated `SubnetId`.
    pub attestation_committee_index: CommitteeIndex,
    /// The slot in which to subscribe.
    pub slot: Slot,
    /// Committee count at slot to subscribe.
    pub committee_count_at_slot: u64,
    /// If true, the validator is an aggregator and the beacon node should aggregate attestations
    /// for this slot.
    pub is_aggregator: bool,
}
