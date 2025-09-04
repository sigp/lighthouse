use kzg::KzgCommitment;

use crate::test_utils::TestRandom;

impl TestRandom for KzgCommitment {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        KzgCommitment(<[u8; 48] as TestRandom>::random_for_test(rng))
    }
}
