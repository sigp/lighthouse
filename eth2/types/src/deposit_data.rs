use crate::test_utils::TestRandom;
use crate::*;
use bls::{PublicKeyBytes, SignatureBytes};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.11.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    pub amount: u64,
    pub signature: SignatureBytes,
}

impl DepositData {
    /// Create a `DepositMessage` corresponding to this `DepositData`, for signature verification.
    ///
    /// Spec v0.11.1
    pub fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey.clone(),
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }

    /// Generate the signature for a given DepositData details.
    ///
    /// Spec v0.11.1
    pub fn create_signature(&self, secret_key: &SecretKey, spec: &ChainSpec) -> SignatureBytes {
        let domain = spec.get_deposit_domain();
        let msg = self.as_deposit_message().signing_root(domain);

        SignatureBytes::from(Signature::new(msg.as_bytes(), secret_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(DepositData);
}
