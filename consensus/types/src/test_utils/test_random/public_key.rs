use bls::{PublicKey, SecretKey};

use crate::test_utils::TestRandom;

impl TestRandom for PublicKey {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        SecretKey::random_for_test(rng).public_key()
    }
}
