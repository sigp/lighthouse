use super::{AggregateSignature, EthSpec, SignedRoot};
use crate::slot_data::SlotData;
use crate::{test_utils::TestRandom, BitVector, Hash256, Slot, SyncCommitteeMessage};
use safe_arith::ArithError;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq)]
pub enum Error {
    SszTypesError(ssz_types::Error),
    AlreadySigned(usize),
    SubnetCountIsZero(ArithError),
}

/// An aggregation of `SyncCommitteeMessage`s, used in creating a `SignedContributionAndProof`.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct SyncCommitteeContribution<T: EthSpec> {
    pub slot: Slot,
    pub beacon_block_root: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
    pub aggregation_bits: BitVector<T::SyncSubcommitteeSize>,
    pub signature: AggregateSignature,
}

impl<T: EthSpec> SyncCommitteeContribution<T> {
    /// Create a `SyncCommitteeContribution` from:
    ///
    /// - `message`: A single `SyncCommitteeMessage`.
    /// - `subcommittee_index`: The subcommittee this contribution pertains to out of the broader
    ///     sync committee. This can be determined from the `SyncSubnetId` of the gossip subnet
    ///     this message was seen on.
    /// - `validator_sync_committee_index`: The index of the validator **within** the subcommittee.
    pub fn from_message(
        message: &SyncCommitteeMessage,
        subcommittee_index: u64,
        validator_sync_committee_index: usize,
    ) -> Result<Self, Error> {
        let mut bits = BitVector::new();
        bits.set(validator_sync_committee_index, true)
            .map_err(Error::SszTypesError)?;
        Ok(Self {
            slot: message.slot,
            beacon_block_root: message.beacon_block_root,
            subcommittee_index,
            aggregation_bits: bits,
            signature: AggregateSignature::from(&message.signature),
        })
    }

    /// Are the aggregation bitfields of these sync contribution disjoint?
    pub fn signers_disjoint_from(&self, other: &Self) -> bool {
        self.aggregation_bits
            .intersection(&other.aggregation_bits)
            .is_zero()
    }

    /// Aggregate another `SyncCommitteeContribution` into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: &Self) {
        debug_assert_eq!(self.slot, other.slot);
        debug_assert_eq!(self.beacon_block_root, other.beacon_block_root);
        debug_assert_eq!(self.subcommittee_index, other.subcommittee_index);
        debug_assert!(self.signers_disjoint_from(other));

        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.signature.add_assign_aggregate(&other.signature);
    }
}

impl SignedRoot for Hash256 {}

/// This is not in the spec, but useful for determining uniqueness of sync committee contributions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct SyncContributionData {
    pub slot: Slot,
    pub beacon_block_root: Hash256,
    pub subcommittee_index: u64,
}

impl SyncContributionData {
    pub fn from_contribution<T: EthSpec>(signing_data: &SyncCommitteeContribution<T>) -> Self {
        Self {
            slot: signing_data.slot,
            beacon_block_root: signing_data.beacon_block_root,
            subcommittee_index: signing_data.subcommittee_index,
        }
    }
}

impl<T: EthSpec> SlotData for SyncCommitteeContribution<T> {
    fn get_slot(&self) -> Slot {
        self.slot
    }
}

impl SlotData for SyncContributionData {
    fn get_slot(&self) -> Slot {
        self.slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(SyncCommitteeContribution<MainnetEthSpec>);
}
