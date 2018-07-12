extern crate rand;

use super::bls::Keypair;
use self::rand::thread_rng;

// Returns a keypair for use in testing purposes.
pub fn get_dangerous_test_keypair() -> Keypair {
    let mut rng = thread_rng();
    Keypair::generate(&mut rng)
}
