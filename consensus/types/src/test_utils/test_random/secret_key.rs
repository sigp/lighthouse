use bls::SecretKey;

use crate::test_utils::TestRandom;

impl TestRandom for SecretKey {
    fn random_for_test(_rng: &mut impl rand::RngCore) -> Self {
        // TODO: Not deterministic generation. Using `SecretKey::deserialize` results in
        // `BlstError(BLST_BAD_ENCODING)`, need to debug with blst source on what encoding expects.
        SecretKey::random()
    }
}
