use crate::test_utils::TestRandom;
use crate::*;
use bls::{PublicKeyBytes, SignatureBytes};
use std::convert::From;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.9.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct DepositMessage {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    pub amount: u64,
}

impl DepositMessage {
    /// Generate the signature for a given DepositMessage details.
    ///
    /// Spec v0.9.1
    pub fn create_signature(&self, secret_key: &SecretKey, spec: &ChainSpec) -> SignatureBytes {
        let msg = self.signed_root();
        let domain = spec.get_deposit_domain();

        SignatureBytes::from(Signature::new(msg.as_slice(), domain, secret_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(DepositMessage);
}
