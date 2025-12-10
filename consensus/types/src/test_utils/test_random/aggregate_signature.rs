use bls::{AggregateSignature, Signature};

use crate::test_utils::TestRandom;

impl TestRandom for AggregateSignature {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        let signature = Signature::random_for_test(rng);
        let mut aggregate_signature = AggregateSignature::infinity();
        aggregate_signature.add_assign(&signature);
        aggregate_signature
    }
}
