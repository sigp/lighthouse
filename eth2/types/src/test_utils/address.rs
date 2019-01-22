use super::TestRandom;
use crate::Address;
use rand::RngCore;

impl<T: RngCore> TestRandom<T> for Address {
    fn random_for_test(rng: &mut T) -> Self {
        let mut key_bytes = vec![0; 20];
        rng.fill_bytes(&mut key_bytes);
        Address::from(&key_bytes[..])
    }
}
