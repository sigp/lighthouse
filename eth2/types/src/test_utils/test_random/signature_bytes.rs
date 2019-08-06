use bls::{SignatureBytes, BLS_SIG_BYTE_SIZE};

use super::*;
use std::convert::From;

impl TestRandom for SignatureBytes {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        //50-50 chance for signature to be "valid" or invalid
        if bool::random_for_test(rng) {
            //valid signature
            SignatureBytes::from(Signature::random_for_test(rng))
        } else {
            //invalid signature, just random bytes
            SignatureBytes::from_bytes(&<[u8; BLS_SIG_BYTE_SIZE]>::random_for_test(rng)).unwrap()
        }
    }
}
