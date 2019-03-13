use crate::test_utils::TestRandom;
use crate::*;
use bls::{Keypair, PublicKey, Signature};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::{SignedRoot, TreeHash};
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// The data supplied by the user to the deposit contract.
///
/// Spec v0.4.0
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
    pub proof_of_possession: Signature,
}

impl DepositInput {
    /// Generate the 'proof_of_posession' signature for a given DepositInput details.
    ///
    /// Spec v0.4.0
    pub fn create_proof_of_possession(
        keypair: &Keypair,
        withdrawal_credentials: &Hash256,
        domain: u64,
    ) -> Signature {
        let signable_deposit_input = DepositInput {
            pubkey: keypair.pk.clone(),
            withdrawal_credentials: withdrawal_credentials.clone(),
            proof_of_possession: Signature::empty_signature(),
        };
        let msg = signable_deposit_input.signed_root();

        Signature::new(msg.as_slice(), domain, &keypair.sk)
    }

    /// Verify that proof-of-possession is valid.
    ///
    /// Spec v0.4.0
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
}
