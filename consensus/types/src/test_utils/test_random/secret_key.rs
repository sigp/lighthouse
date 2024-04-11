use super::*;

impl TestRandom for SecretKey {
    fn random_for_test(_rng: &mut impl RngCore) -> Self {
        SecretKey::random()
    }
}
