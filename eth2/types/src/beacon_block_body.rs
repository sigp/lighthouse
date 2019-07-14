use crate::test_utils::{graffiti_from_hex_str, TestRandom};
use crate::*;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// The body of a `BeaconChain` block, containing operations.
///
/// Spec v0.6.3
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
)]
pub struct BeaconBlockBody {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    #[serde(deserialize_with = "graffiti_from_hex_str")]
    pub graffiti: [u8; 32],
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
    cached_tree_hash_tests!(BeaconBlockBody);
}
