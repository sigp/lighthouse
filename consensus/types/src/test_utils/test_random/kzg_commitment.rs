use super::*;
use crate::KzgCommitment;

impl TestRandom for KzgCommitment {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        KzgCommitment(<[u8; 48] as TestRandom>::random_for_test(rng))
    }
}
