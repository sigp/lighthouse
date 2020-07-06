use std::convert::From;

use bls::{PublicKeyBytes, BLS_PUBLIC_KEY_BYTE_SIZE};

use super::*;

impl TestRandom for PublicKeyBytes {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        //50-50 chance for signature to be "valid" or invalid
        if bool::random_for_test(rng) {
            //valid signature
            PublicKeyBytes::from(PublicKey::random_for_test(rng))
        } else {
            //invalid signature, just random bytes
            PublicKeyBytes::from_bytes(&<[u8; BLS_PUBLIC_KEY_BYTE_SIZE]>::random_for_test(rng))
                .unwrap()
        }
    }
}
