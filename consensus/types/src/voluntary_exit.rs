use crate::{
    test_utils::TestRandom, ChainSpec, Domain, Epoch, ForkName, Hash256, SecretKey, SignedRoot,
    SignedVoluntaryExit,
};

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    pub epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}

impl SignedRoot for VoluntaryExit {}

impl VoluntaryExit {
    pub fn sign(
        self,
        secret_key: &SecretKey,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedVoluntaryExit {
        let fork_name = spec.fork_name_at_epoch(self.epoch);
        let fork_version = match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
                spec.fork_version_for_name(fork_name)
            }
            // EIP-7044
            ForkName::Deneb | ForkName::Electra => spec.fork_version_for_name(ForkName::Capella),
        };
        let domain =
            spec.compute_domain(Domain::VoluntaryExit, fork_version, genesis_validators_root);

        let message = self.signing_root(domain);
        SignedVoluntaryExit {
            message: self,
            signature: secret_key.sign(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(VoluntaryExit);
}
