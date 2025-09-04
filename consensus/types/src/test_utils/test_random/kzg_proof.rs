use kzg::{BYTES_PER_COMMITMENT, KzgProof};

use crate::test_utils::TestRandom;

impl TestRandom for KzgProof {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        let mut bytes = [0; BYTES_PER_COMMITMENT];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
