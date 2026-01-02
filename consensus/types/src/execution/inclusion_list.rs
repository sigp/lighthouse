use crate::test_utils::TestRandom;
use crate::{EthSpec, Hash256, SignedRoot, Slot, Transactions};
use bls::{PublicKeyBytes, Signature};
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type InclusionListCommittee<E> = FixedVector<u64, <E as EthSpec>::InclusionListCommitteeSize>;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Educe, Decode, TreeHash, TestRandom)]
#[serde(bound = "E: EthSpec")]
#[educe(PartialEq, Eq, Hash(bound(E: EthSpec)))]
pub struct InclusionList<E: EthSpec> {
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub inclusion_list_committee_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<E>,
}

impl<E: EthSpec> SignedRoot for InclusionList<E> {}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Educe)]
#[serde(bound = "E: EthSpec")]
#[educe(PartialEq, Eq, Hash(bound(E: EthSpec)))]
pub struct SignedInclusionList<E: EthSpec> {
    pub message: InclusionList<E>,
    pub signature: Signature,
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub struct InclusionListDuty {
    /// The slot during which the validator must produce an inclusion list.
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    /// The index of the validator.
    pub validator_index: u64,
    /// The hash tree root of the inclusion list committee.
    pub committee_root: Hash256,
    /// The pubkey of the validator.
    pub pubkey: PublicKeyBytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(InclusionList<MainnetEthSpec>);
}
