use super::*;

impl TestRandom for AggregateSignature {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let signature = Signature::random_for_test(rng);
        let mut aggregate_signature = AggregateSignature::infinity();
        aggregate_signature.add_assign(&signature);
        aggregate_signature
    }
}
