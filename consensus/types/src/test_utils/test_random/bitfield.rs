use super::*;
use smallvec::smallvec;

impl<N: Unsigned + Clone> TestRandom for BitList<N> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let initial_len = std::cmp::max(1, (N::to_usize() + 7) / 8);
        let mut raw_bytes = smallvec![0; initial_len];
        rng.fill_bytes(&mut raw_bytes);

        let non_zero_bytes = raw_bytes
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, byte)| (*byte > 0).then_some(i + 1))
            .unwrap_or(0);

        if non_zero_bytes < initial_len {
            raw_bytes.truncate(non_zero_bytes);
        }

        Self::from_bytes(raw_bytes).expect("we generate a valid BitList")
    }
}

impl<N: Unsigned + Clone> TestRandom for BitVector<N> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut raw_bytes = smallvec![0; std::cmp::max(1, (N::to_usize() + 7) / 8)];
        rng.fill_bytes(&mut raw_bytes);
        // If N isn't divisible by 8
        // zero out bits greater than N
        if let Some(last_byte) = raw_bytes.last_mut() {
            let mut mask = 0;
            for i in 0..N::to_usize() % 8 {
                mask |= 1 << i;
            }
            *last_byte &= mask;
        }
        Self::from_bytes(raw_bytes).expect("we generate a valid BitVector")
    }
}
