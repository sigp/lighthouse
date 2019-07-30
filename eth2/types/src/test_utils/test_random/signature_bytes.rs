use bls::{BLS_SIG_BYTE_SIZE, SecretKey, SignatureBytes};

use super::*;

impl TestRandom for SignatureBytes {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        //50-50 chance for signature to be "valid" or invalid
        if bool::random_for_test(rng) {
            //valid signature
            SignatureBytes::new(Signature::random_for_test(rng))
        } else {
            //invalid signature, just random bytes
            SignatureBytes::new_from_bytes(&<[u8; BLS_SIG_BYTE_SIZE]>::random_for_test(rng))
        }
    }
}