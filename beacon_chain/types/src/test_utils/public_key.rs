use super::TestRandom;
use bls::{PublicKey, SecretKey};
use rand::RngCore;

impl<T: RngCore> TestRandom<T> for PublicKey {
    fn random_for_test(rng: &mut T) -> Self {
        let secret_key = SecretKey::random_for_test(rng);
        PublicKey::from_secret_key(&secret_key)
    }
}
