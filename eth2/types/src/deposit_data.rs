use crate::test_utils::TestRandom;
use crate::*;
use bls::{PublicKey, Signature};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::{SignedRoot, TreeHash};
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.6.1
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
    CachedTreeHash,
    TestRandom,
)]
pub struct DepositData {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub amount: u64,
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

impl DepositData {
    /// Generate the signature for a given DepositData details.
    ///
    /// Spec v0.5.1
    pub fn create_signature(
        &self,
        secret_key: &SecretKey,
        epoch: Epoch,
        fork: &Fork,
        spec: &ChainSpec,
    ) -> Signature {
        let msg = self.signed_root();
        let domain = spec.get_domain(epoch, Domain::Deposit, fork);

        Signature::new(msg.as_slice(), domain, secret_key)
    }

    /// Verify that proof-of-possession is valid.
    ///
    /// Spec v0.5.1
    pub fn validate_signature(&self, epoch: Epoch, fork: &Fork, spec: &ChainSpec) -> bool {
        let msg = self.signed_root();
        let domain = spec.get_domain(epoch, Domain::Deposit, fork);

        self.signature.verify(&msg, domain, &self.pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(DepositData);
    cached_tree_hash_tests!(DepositData);

    #[test]
    fn can_create_and_validate() {
        let spec = ChainSpec::foundation();
        let fork = Fork::genesis(&spec);
        let keypair = Keypair::random();
        let epoch = Epoch::new(0);

        let mut deposit_input = DepositData {
            pubkey: keypair.pk.clone(),
            amount: 0,
            withdrawal_credentials: Hash256::zero(),
            signature: Signature::empty_signature(),
        };

        deposit_input.signature = deposit_input.create_signature(&keypair.sk, epoch, &fork, &spec);

        assert!(deposit_input.validate_signature(epoch, &fork, &spec));
    }
}
