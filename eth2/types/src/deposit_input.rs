use crate::test_utils::TestRandom;
use crate::*;
use bls::{PublicKey, Signature};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::{SignedRoot, TreeHash};
use tree_hash_derive::{SignedRoot, TreeHash};

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.5.1
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
pub struct DepositInput {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    #[signed_root(skip_hashing)]
    pub proof_of_possession: Signature,
}

impl DepositInput {
    /// Generate the 'proof_of_posession' signature for a given DepositInput details.
    ///
    /// Spec v0.5.1
    pub fn create_proof_of_possession(
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
    pub fn validate_proof_of_possession(
        &self,
        epoch: Epoch,
        fork: &Fork,
        spec: &ChainSpec,
    ) -> bool {
        let msg = self.signed_root();
        let domain = spec.get_domain(epoch, Domain::Deposit, fork);

        self.proof_of_possession.verify(&msg, domain, &self.pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(DepositInput);

    #[test]
    fn can_create_and_validate() {
        let spec = ChainSpec::foundation();
        let fork = Fork::genesis(&spec);
        let keypair = Keypair::random();
        let epoch = Epoch::new(0);

        let mut deposit_input = DepositInput {
            pubkey: keypair.pk.clone(),
            withdrawal_credentials: Hash256::zero(),
            proof_of_possession: Signature::empty_signature(),
        };

        deposit_input.proof_of_possession =
            deposit_input.create_proof_of_possession(&keypair.sk, epoch, &fork, &spec);

        assert!(deposit_input.validate_proof_of_possession(epoch, &fork, &spec));
    }
}
