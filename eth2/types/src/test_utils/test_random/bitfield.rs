use super::*;
use crate::Bitfield;

impl TestRandom for Bitfield {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut raw_bytes = vec![0; 32];
        rng.fill_bytes(&mut raw_bytes);
        Bitfield::from_bytes(&raw_bytes)
    }
}
