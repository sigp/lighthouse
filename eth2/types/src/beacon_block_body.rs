use crate::test_utils::TestRandom;
use crate::utils::{graffiti_from_hex_str, graffiti_to_hex_str};
use crate::*;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The body of a `BeaconChain` block, containing operations.
///
/// Spec v0.8.0
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct BeaconBlockBody<T: EthSpec> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    #[serde(
        serialize_with = "graffiti_to_hex_str",
        deserialize_with = "graffiti_from_hex_str"
    )]
    pub graffiti: [u8; 32],
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashing<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<Attestation<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<VoluntaryExit, T::MaxVoluntaryExits>,
    pub transfers: VariableList<Transfer, T::MaxTransfers>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlockBody<MainnetEthSpec>);
}
