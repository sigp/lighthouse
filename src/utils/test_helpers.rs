extern crate rand;

use super::bls::Keypair;
use self::rand::{ SeedableRng, XorShiftRng };

// Returns a keypair for use in testing purposes.
pub fn get_dangerous_test_keypair() -> Keypair {
    let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 
                                         0xd62f276c, 
                                         0xb963afd0, 
                                         0x5455863d]);
    Keypair::generate(&mut rng)
}
