use bls::PUBLIC_KEY_BYTES_LEN;

use super::*;

impl TestRandom for PublicKeyBytes {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        //50-50 chance for signature to be "valid" or invalid
        if bool::random_for_test(rng) {
            //valid signature
            PublicKeyBytes::from(PublicKey::random_for_test(rng))
        } else {
            //invalid signature, just random bytes
            PublicKeyBytes::deserialize(&<[u8; PUBLIC_KEY_BYTES_LEN]>::random_for_test(rng))
                .unwrap()
        }
    }
}
