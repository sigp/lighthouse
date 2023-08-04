use super::*;
use crate::SigpBlob;

impl<E: EthSpec> TestRandom for SigpBlob<E> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        SigpBlob::random_valid(rng).expect("should create valid blob")
    }
}
