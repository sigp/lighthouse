use crate::{EthSpec, ForkName, Hash256, SignedRoot, Slot, Transactions};
use bls::{PublicKeyBytes, Signature};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use tree_hash_derive::TreeHash;

pub type InclusionListCommittee<E> = FixedVector<u64, <E as EthSpec>::InclusionListCommitteeSize>;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Educe, Decode, TreeHash)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[serde(bound = "E: EthSpec")]
#[educe(PartialEq, Eq, Hash(bound(E: EthSpec)))]
#[context_deserialize(ForkName)]
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
#[context_deserialize(ForkName)]
pub struct SignedInclusionList<E: EthSpec> {
    pub message: InclusionList<E>,
    pub signature: Signature,
}

/// Inclusion list transactions, (de)serialized as a flat JSON array of hex `DATA` strings
/// per the beacon-APIs `produceInclusionList` response (`data: Bellatrix.Transactions`).
#[derive(Debug, Clone, PartialEq)]
pub struct InclusionListTransactions<E: EthSpec>(pub Transactions<E>);

impl<E: EthSpec> Serialize for InclusionListTransactions<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ssz_types::serde_utils::list_of_hex_var_list::serialize(&self.0, serializer)
    }
}

impl<'de, E: EthSpec> Deserialize<'de> for InclusionListTransactions<E> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ssz_types::serde_utils::list_of_hex_var_list::deserialize(deserializer).map(Self)
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub struct InclusionListDuty {
    /// The slot during which the validator must produce an inclusion list.
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    /// The index of the validator.
    pub validator_index: u64,
    /// The hash tree root of the inclusion list committee.
    pub inclusion_list_committee_root: Hash256,
    /// The pubkey of the validator.
    pub pubkey: PublicKeyBytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(InclusionList<MainnetEthSpec>);
}
