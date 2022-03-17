use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
#[superstruct(
    variants(Base, Altair, Merge),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            Derivative,
        ),
        derivative(PartialEq, Hash(bound = "T: EthSpec, Payload: ExecPayload<T>")),
        serde(bound = "T: EthSpec, Payload: ExecPayload<T>", deny_unknown_fields),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "T: EthSpec, Payload: ExecPayload<T>")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct BeaconBlockBody<T: EthSpec, Payload: ExecPayload<T> = FullPayload<T>> {
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
    // We flatten the execution payload so that serde can use the name of the inner type,
    // either `execution_payload` for full payloads, or `execution_payload_header` for blinded
    // payloads.
    #[superstruct(only(Merge))]
    #[serde(flatten)]
    pub execution_payload: Payload,
    #[superstruct(only(Base, Altair))]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    pub _phantom: PhantomData<Payload>,
}

impl<'a, T: EthSpec> BeaconBlockBodyRef<'a, T> {
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
