extern crate rand;

use super::bls::Keypair;
use self::rand::thread_rng;

// Returns a keypair for use in testing purposes.
// It is dangerous because we provide no guarantees
// that the private key is unique or in-fact private.
pub fn get_dangerous_test_keypair() -> Keypair {
    let mut rng = thread_rng();
    Keypair::generate(&mut rng)
}
