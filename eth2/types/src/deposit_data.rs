use crate::test_utils::TestRandom;
use crate::*;
use bls::{PublicKeyBytes, SignatureBytes};
use std::convert::From;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::{SignedRoot, TreeHash};
use tree_hash_derive::{SignedRoot, TreeHash};

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.8.0
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    SignedRoot,
    TreeHash,
    TestRandom,
)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    pub amount: u64,
    #[signed_root(skip_hashing)]
    pub signature: SignatureBytes,
}

impl DepositData {
    /// Generate the signature for a given DepositData details.
    ///
    /// Spec v0.8.1
    pub fn create_signature(
        &self,
        secret_key: &SecretKey,
        epoch: Epoch,
        fork: &Fork,
        spec: &ChainSpec,
    ) -> SignatureBytes {
        let msg = self.signed_root();
        let domain = spec.get_domain(epoch, Domain::Deposit, fork);

        SignatureBytes::from(Signature::new(msg.as_slice(), domain, secret_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(DepositData);
}
