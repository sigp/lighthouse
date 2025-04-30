use super::*;

impl TestRandom for Signature {
    fn random_for_test(_rng: &mut impl RngCore) -> Self {
        // TODO: `SecretKey::random_for_test` does not return a deterministic signature. Since this
        // signature will not pass verification we could just return the generator point or the
        // generator point multiplied by a random scalar if we want disctint signatures.
        Signature::infinity().expect("infinity signature is valid")
    }
}
