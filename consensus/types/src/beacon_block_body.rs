use crate::execution_payload::ExecTransactions;
use crate::test_utils::TestRandom;
use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
#[superstruct(
    variants(Base, Altair, Merge),
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
        serde(bound = "T: EthSpec, Txns: Transactions<T>", deny_unknown_fields),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec, Txns: Transactions<T>")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct BeaconBlockBody<T: EthSpec, Txns: Transactions<T> = ExecTransactions<T>> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Graffiti,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashing<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<Attestation<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    #[superstruct(only(Altair, Merge))]
    pub sync_aggregate: SyncAggregate<T>,
    #[superstruct(only(Merge))]
    pub execution_payload: ExecutionPayload<T, Txns>,
    #[superstruct(only(Base, Altair))]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    pub _phantom: PhantomData<Txns>,
}

impl<'a, T: EthSpec, Txns: Transactions<T>> BeaconBlockBodyRef<'a, T, Txns> {
    /// Access the sync aggregate from the block's body, if one exists.
    pub fn sync_aggregate(self) -> Option<&'a SyncAggregate<T>> {
        match self {
            BeaconBlockBodyRef::Base(_) => None,
            BeaconBlockBodyRef::Altair(inner) => Some(&inner.sync_aggregate),
            BeaconBlockBodyRef::Merge(inner) => Some(&inner.sync_aggregate),
        }
    }

    /// Access the execution payload from the block's body, if one exists.
    pub fn execution_payload(self) -> Option<&'a ExecutionPayload<T, Txns>> {
        match self {
            BeaconBlockBodyRef::Base(_) => None,
            BeaconBlockBodyRef::Altair(_) => None,
            BeaconBlockBodyRef::Merge(inner) => Some(&inner.execution_payload),
        }
    }

    /// Get the fork_name of this object
    pub fn fork_name(self) -> ForkName {
        match self {
            BeaconBlockBodyRef::Base { .. } => ForkName::Base,
            BeaconBlockBodyRef::Altair { .. } => ForkName::Altair,
            BeaconBlockBodyRef::Merge { .. } => ForkName::Merge,
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
