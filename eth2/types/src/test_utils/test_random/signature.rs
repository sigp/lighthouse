use super::*;
use bls::{SecretKey, Signature};

impl TestRandom for Signature {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let secret_key = SecretKey::random_for_test(rng);
        let mut message = vec![0; 32];
        rng.fill_bytes(&mut message);

        Signature::new(&message, 0, &secret_key)
    }
}
