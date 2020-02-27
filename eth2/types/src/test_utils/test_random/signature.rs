use super::*;
use bls::{SecretKey, Signature};

impl TestRandom for Signature {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let secret_key = SecretKey::random_for_test(rng);
        secret_key.sign(Hash256::random_for_test(rng))
    }
}
