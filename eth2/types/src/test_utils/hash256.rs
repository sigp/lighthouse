use super::TestRandom;
use crate::Hash256;
use rand::RngCore;

impl<T: RngCore> TestRandom<T> for Hash256 {
    fn random_for_test(rng: &mut T) -> Self {
        let mut key_bytes = vec![0; 32];
        rng.fill_bytes(&mut key_bytes);
        Hash256::from_slice(&key_bytes[..])
    }
}
