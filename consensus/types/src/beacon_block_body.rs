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
    variants(Base, Altair, Merge, Shanghai),
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
    #[superstruct(only(Altair, Merge, Shanghai))]
    pub sync_aggregate: SyncAggregate<T>,
    // We flatten the execution payload so that serde can use the name of the inner type,
    // either `execution_payload` for full payloads, or `execution_payload_header` for blinded
    // payloads.
    #[superstruct(only(Merge, Shanghai))]
    #[serde(flatten)]
    pub execution_payload: Payload,
    #[superstruct(only(Shanghai))]
    pub blob_kzgs: VariableList<KZGCommitment, T::MaxObjectListSize>,
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
            BeaconBlockBodyRef::Shanghai { .. } => ForkName::Shanghai,
        }
    }
}

// We can convert pre-Bellatrix block bodies without payloads into block bodies "with" payloads.
impl<E: EthSpec> From<BeaconBlockBodyBase<E, BlindedPayload<E>>>
    for BeaconBlockBodyBase<E, FullPayload<E>>
{
    fn from(body: BeaconBlockBodyBase<E, BlindedPayload<E>>) -> Self {
        let BeaconBlockBodyBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            _phantom,
        } = body;

        BeaconBlockBodyBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> From<BeaconBlockBodyAltair<E, BlindedPayload<E>>>
    for BeaconBlockBodyAltair<E, FullPayload<E>>
{
    fn from(body: BeaconBlockBodyAltair<E, BlindedPayload<E>>) -> Self {
        let BeaconBlockBodyAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            _phantom,
        } = body;

        BeaconBlockBodyAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            _phantom: PhantomData,
        }
    }
}

// Likewise bodies with payloads can be transformed into bodies without.
impl<E: EthSpec> From<BeaconBlockBodyBase<E, FullPayload<E>>>
    for (
        BeaconBlockBodyBase<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    fn from(body: BeaconBlockBodyBase<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            _phantom,
        } = body;

        (
            BeaconBlockBodyBase {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                _phantom: PhantomData,
            },
            None,
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyAltair<E, FullPayload<E>>>
    for (
        BeaconBlockBodyAltair<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    fn from(body: BeaconBlockBodyAltair<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            _phantom,
        } = body;

        (
            BeaconBlockBodyAltair {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                _phantom: PhantomData,
            },
            None,
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyMerge<E, FullPayload<E>>>
    for (
        BeaconBlockBodyMerge<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    fn from(body: BeaconBlockBodyMerge<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyMerge {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayload { execution_payload },
        } = body;

        (
            BeaconBlockBodyMerge {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload: BlindedPayload {
                    execution_payload_header: From::from(&execution_payload),
                },
            },
            Some(execution_payload),
        )
    }
}

// We can clone a full block into a blinded block, without cloning the payload.
impl<E: EthSpec> BeaconBlockBodyBase<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBase<E, BlindedPayload<E>> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> BeaconBlockBodyAltair<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyAltair<E, BlindedPayload<E>> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> BeaconBlockBodyMerge<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyMerge<E, BlindedPayload<E>> {
        let BeaconBlockBodyMerge {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayload { execution_payload },
        } = self;

        BeaconBlockBodyMerge {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload: BlindedPayload {
                execution_payload_header: From::from(execution_payload),
            },
        }
    }
}

impl<E: EthSpec> From<BeaconBlockBody<E, FullPayload<E>>>
    for (
        BeaconBlockBody<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    fn from(body: BeaconBlockBody<E, FullPayload<E>>) -> Self {
        map_beacon_block_body!(body, |inner, cons| {
            let (block, payload) = inner.into();
            (cons(block), payload)
        })
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
