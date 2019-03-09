use super::TestRandom;
use bls::{SecretKey, Signature};
use rand::RngCore;

impl<T: RngCore> TestRandom<T> for Signature {
    fn random_for_test(rng: &mut T) -> Self {
        let secret_key = SecretKey::random_for_test(rng);
        let mut message = vec![0; 32];
        rng.fill_bytes(&mut message);

        Signature::new(&message, 0, &secret_key)
    }
}
