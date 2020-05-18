use super::*;
use crate::Address;

impl TestRandom for Address {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut key_bytes = vec![0; 20];
        rng.fill_bytes(&mut key_bytes);
        Address::from_slice(&key_bytes[..])
    }
}
