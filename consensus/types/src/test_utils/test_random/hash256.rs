use crate::{core::Hash256, test_utils::TestRandom};

impl TestRandom for Hash256 {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        let mut key_bytes = vec![0; 32];
        rng.fill_bytes(&mut key_bytes);
        Hash256::from_slice(&key_bytes[..])
    }
}
