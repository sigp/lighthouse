use super::*;
use kzg_types::BYTES_PER_COMMITMENT;
use kzg_types::KzgProof;

impl TestRandom for KzgProof {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; BYTES_PER_COMMITMENT];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
