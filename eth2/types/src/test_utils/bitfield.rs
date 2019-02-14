use super::super::Bitfield;
use super::TestRandom;
use rand::RngCore;

impl<T: RngCore> TestRandom<T> for Bitfield {
    fn random_for_test(rng: &mut T) -> Self {
        let mut raw_bytes = vec![0; 32];
        rng.fill_bytes(&mut raw_bytes);
        Bitfield::from_bytes(&raw_bytes)
    }
}
