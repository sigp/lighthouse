use crate::test_utils::TestRandom;
use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
#[superstruct(
    variants(Base, Altair),
    variant_attributes(
        derive(
            Debug,
            PartialEq,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom
        ),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    )
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct BeaconBlockBody<T: EthSpec> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Graffiti,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashing<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<Attestation<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    #[superstruct(only(Altair))]
    pub sync_aggregate: SyncAggregate<T>,
}

impl<'a, T: EthSpec> BeaconBlockBodyRef<'a, T> {
    /// Access the sync aggregate from the block's body, if one exists.
    pub fn sync_aggregate(self) -> Option<&'a SyncAggregate<T>> {
        match self {
            BeaconBlockBodyRef::Base(_) => None,
            BeaconBlockBodyRef::Altair(inner) => Some(&inner.sync_aggregate),
        }
    }
}

#[cfg(test)]
mod tests {
    mod base {
        use super::super::*;
        ssz_and_tree_hash_tests!(BeaconBlockBodyBase<MainnetEthSpec>);
    }
    mod altair {
        use super::super::*;
        ssz_and_tree_hash_tests!(BeaconBlockBodyAltair<MainnetEthSpec>);
    }
}
