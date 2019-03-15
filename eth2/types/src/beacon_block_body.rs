use super::{Attestation, AttesterSlashing, Deposit, ProposerSlashing, Transfer, VoluntaryExit};
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// The body of a `BeaconChain` block, containing operations.
///
/// Spec v0.4.0
#[derive(
    Debug, PartialEq, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct BeaconBlockBody {
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
