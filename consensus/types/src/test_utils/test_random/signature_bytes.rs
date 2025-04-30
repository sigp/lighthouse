use bls::SIGNATURE_BYTES_LEN;

use super::*;

impl TestRandom for SignatureBytes {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        //50-50 chance for signature to be "valid" or invalid
        if bool::random_for_test(rng) {
            //valid signature
            SignatureBytes::from(Signature::random_for_test(rng))
        } else {
            //invalid signature, just random bytes
            SignatureBytes::deserialize(&<[u8; SIGNATURE_BYTES_LEN]>::random_for_test(rng)).unwrap()
        }
    }
}
