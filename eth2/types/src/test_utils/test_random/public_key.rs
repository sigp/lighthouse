use super::*;
use bls::{PublicKey, SecretKey};

impl TestRandom for PublicKey {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let secret_key = SecretKey::random_for_test(rng);
        PublicKey::from_secret_key(&secret_key)
    }
}
