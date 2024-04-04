use super::*;

impl TestRandom for PublicKey {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        SecretKey::random_for_test(rng).public_key()
    }
}
