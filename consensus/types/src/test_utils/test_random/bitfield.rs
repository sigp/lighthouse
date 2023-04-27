use super::*;
use crate::{BitList, BitVector, Unsigned};
use smallvec::smallvec;

impl<N: Unsigned + Clone> TestRandom for BitList<N> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let initial_len = std::cmp::max(1, (N::to_usize() + 7) / 8);
        let mut raw_bytes = smallvec![0; initial_len];
        rng.fill_bytes(&mut raw_bytes);

        let highest_set_bit = raw_bytes
            .iter()
            .enumerate()
            .rev()
            .find(|(_, byte)| **byte > 0)
            .map(|(i, byte)| i * 8 + 7 - byte.leading_zeros() as usize)
            .unwrap_or(0);

        let actual_len = highest_set_bit / 8 + 1;

        if actual_len < initial_len {
            raw_bytes.truncate(actual_len);
        }

        Self::from_bytes(raw_bytes).expect("we generate a valid BitList")
    }
}

impl<N: Unsigned + Clone> TestRandom for BitVector<N> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut raw_bytes = smallvec![0; std::cmp::max(1, (N::to_usize() + 7) / 8)];
        rng.fill_bytes(&mut raw_bytes);
        Self::from_bytes(raw_bytes).expect("we generate a valid BitVector")
    }
}
