use super::*;
use kzg::BYTES_PER_COMMITMENT;

impl TestRandom for KzgProof {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; BYTES_PER_COMMITMENT];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
