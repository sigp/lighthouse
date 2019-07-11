use super::*;
use crate::{BitList, BitVector, Unsigned};

impl<N: Unsigned + Clone> TestRandom for BitList<N> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut raw_bytes = vec![0; std::cmp::max(1, (N::to_usize() + 7) / 8)];
        rng.fill_bytes(&mut raw_bytes);
        Self::from_bytes(raw_bytes).expect("we generate a valid BitList")
    }
}

impl<N: Unsigned + Clone> TestRandom for BitVector<N> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut raw_bytes = vec![0; std::cmp::max(1, (N::to_usize() + 7) / 8)];
        rng.fill_bytes(&mut raw_bytes);
        Self::from_bytes(raw_bytes).expect("we generate a valid BitVector")
    }
}
