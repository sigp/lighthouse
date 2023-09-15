use super::*;
use crate::WrappedBlob;

impl<E: EthSpec> TestRandom for WrappedBlob<E> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        WrappedBlob::random_valid(rng).expect("should create valid blob")
    }
}
