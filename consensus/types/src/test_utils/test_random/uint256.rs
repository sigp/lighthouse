use super::*;

impl TestRandom for Uint256 {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut key_bytes = [0; 32];
        rng.fill_bytes(&mut key_bytes);
        Self::from_little_endian(&key_bytes[..])
    }
}
