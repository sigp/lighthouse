use super::TestRandom;
use bls::{AggregateSignature, Signature};
use rand::RngCore;

impl<T: RngCore> TestRandom<T> for AggregateSignature {
    fn random_for_test(rng: &mut T) -> Self {
        let signature = Signature::random_for_test(rng);
        let mut aggregate_signature = AggregateSignature::new();
        aggregate_signature.add(&signature);
        aggregate_signature
    }
}
