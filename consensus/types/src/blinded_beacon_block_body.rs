use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_types::VariableList;
use superstruct::superstruct;

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
#[superstruct(
    variants(Base, Altair, Merge),
    variant_attributes(
        derive(Debug, PartialEq, Clone, Serialize, Deserialize,),
        serde(bound = "T: EthSpec", deny_unknown_fields),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
pub struct BlindedBeaconBlockBody<T: EthSpec> {
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
    pub execution_payload_header: ExecutionPayloadHeader<T>,
}
