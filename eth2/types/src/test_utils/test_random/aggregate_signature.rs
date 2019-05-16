use super::*;
use bls::{AggregateSignature, Signature};

impl TestRandom for AggregateSignature {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let signature = Signature::random_for_test(rng);
        let mut aggregate_signature = AggregateSignature::new();
        aggregate_signature.add(&signature);
        aggregate_signature
    }
}
