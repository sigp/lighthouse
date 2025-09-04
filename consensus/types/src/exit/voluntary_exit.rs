use bls::SecretKey;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

use crate::{
    core::{ChainSpec, Domain, Epoch, Hash256, SignedRoot},
    exit::SignedVoluntaryExit,
    fork::ForkName,
    test_utils::TestRandom,
};

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[context_deserialize(ForkName)]
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
        let domain = self.get_domain(genesis_validators_root, spec);

        let message = self.signing_root(domain);
        SignedVoluntaryExit {
            message: self,
            signature: secret_key.sign(message),
        }
    }

    pub fn get_domain(&self, genesis_validators_root: Hash256, spec: &ChainSpec) -> Hash256 {
        let fork_name = spec.fork_name_at_epoch(self.epoch);
        let fork_version = if fork_name.deneb_enabled() {
            // EIP-7044
            spec.fork_version_for_name(ForkName::Capella)
        } else {
            spec.fork_version_for_name(fork_name)
        };
        spec.compute_domain(Domain::VoluntaryExit, fork_version, genesis_validators_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(VoluntaryExit);
}
