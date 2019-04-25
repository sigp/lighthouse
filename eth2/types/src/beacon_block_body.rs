use crate::test_utils::TestRandom;
use crate::*;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The body of a `BeaconChain` block, containing operations.
///
/// Spec v0.5.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct BeaconBlockBody {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub attester_slashings: Vec<AttesterSlashing>,
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub voluntary_exits: Vec<VoluntaryExit>,
    pub transfers: Vec<Transfer>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlockBody);
}
