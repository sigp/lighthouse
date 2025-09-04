use bls::{PublicKeyBytes, SecretKey, SignatureBytes};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

use crate::{
    core::{ChainSpec, Hash256, SignedRoot},
    deposit::DepositMessage,
    fork::ForkName,
    test_utils::TestRandom,
};

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[context_deserialize(ForkName)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: SignatureBytes,
}

impl DepositData {
    /// Create a `DepositMessage` corresponding to this `DepositData`, for signature verification.
    ///
    /// Spec v0.12.1
    pub fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }

    /// Generate the signature for a given DepositData details.
    ///
    /// Spec v0.12.1
    pub fn create_signature(&self, secret_key: &SecretKey, spec: &ChainSpec) -> SignatureBytes {
        let domain = spec.get_deposit_domain();
        let msg = self.as_deposit_message().signing_root(domain);

        SignatureBytes::from(secret_key.sign(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(DepositData);
}
