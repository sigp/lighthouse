use super::TestRandom;
use bls::SecretKey;
use rand::RngCore;

impl<T: RngCore> TestRandom<T> for SecretKey {
    fn random_for_test(rng: &mut T) -> Self {
        let mut key_bytes = vec![0; 48];
        rng.fill_bytes(&mut key_bytes);
        /*
         * An `unreachable!` is used here as there's no reason why you cannot constuct a key from a
         * fixed-length byte slice. Also, this should only be used during testing so a panic is
         * acceptable.
         */
        match SecretKey::from_bytes(&key_bytes) {
            Ok(key) => key,
            Err(_) => unreachable!(),
        }
    }
}
