use crate::test_utils::TestRandom;
use crate::*;
use bls::{PublicKeyBytes, SignatureBytes};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.9.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    pub amount: u64,
    pub signature: SignatureBytes,
}

impl DepositData {
    /// Generate the signature for a given DepositData details.
    ///
    /// Spec v0.10.0
    pub fn create_signature(&self, secret_key: &SecretKey, spec: &ChainSpec) -> SignatureBytes {
        let msg = DepositMessage {
            pubkey: self.pubkey.clone(),
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
        .tree_hash_root();
        let domain = spec.get_deposit_domain();

        SignatureBytes::from(Signature::new(msg.as_slice(), domain, secret_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(DepositData);
}
