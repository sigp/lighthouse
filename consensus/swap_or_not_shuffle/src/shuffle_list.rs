use crate::Hash256;
use ethereum_hashing::hash_fixed;
use std::mem;

const SEED_SIZE: usize = 32;
const ROUND_SIZE: usize = 1;
const POSITION_WINDOW_SIZE: usize = 4;
const PIVOT_VIEW_SIZE: usize = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE: usize = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

/// A helper struct to manage the buffer used during shuffling.
struct Buf([u8; TOTAL_SIZE]);

impl Buf {
    /// Create a new buffer from the given `seed`.
    ///
    /// ## Panics
    ///
    /// Panics if `seed.len() != 32`.
    fn new(seed: &[u8]) -> Self {
        let mut buf = [0; TOTAL_SIZE];
        buf[0..SEED_SIZE].copy_from_slice(seed);
        Self(buf)
    }

    /// Set the shuffling round.
    fn set_round(&mut self, round: u8) {
        self.0[SEED_SIZE] = round;
    }

    /// Returns the new pivot. It is "raw" because it has not modulo the list size (this must be
    /// done by the caller).
    fn raw_pivot(&self) -> u64 {
        let digest = hash_fixed(&self.0[0..PIVOT_VIEW_SIZE]);

        let mut bytes = [0; mem::size_of::<u64>()];
        bytes[..].copy_from_slice(&digest[0..mem::size_of::<u64>()]);
        u64::from_le_bytes(bytes)
    }

    /// Add the current position into the buffer.
    fn mix_in_position(&mut self, position: usize) {
        self.0[PIVOT_VIEW_SIZE..].copy_from_slice(&position.to_le_bytes()[0..POSITION_WINDOW_SIZE]);
    }

    /// Hash the entire buffer.
    fn hash(&self) -> Hash256 {
        Hash256::from(hash_fixed(&self.0))
    }
}

/// Applies the swap with a zero-or-all-ones mask, avoiding an unpredictable branch.
#[inline(always)]
fn masked_swap(input: &mut [usize], i: usize, j: usize, bit: u8) {
    debug_assert!(bit <= 1);

    let mask = 0usize.wrapping_sub(bit as usize);
    let left = input[i];
    let right = input[j];
    let delta = (left ^ right) & mask;
    input[i] = left ^ delta;
    input[j] = right ^ delta;
}

/// Shuffles an entire list in-place.
///
/// Note: this is equivalent to the `compute_shuffled_index` function, except it shuffles an entire
/// list not just a single index. With large lists this function has been observed to be 250x
/// faster than running `compute_shuffled_index` across an entire list.
///
/// Credits to [@protolambda](https://github.com/protolambda) for defining this algorithm.
///
/// Shuffles if `forwards == true`, otherwise un-shuffles.
/// It holds that: shuffle_list(shuffle_list(l, r, s, true), r, s, false) == l
///           and: shuffle_list(shuffle_list(l, r, s, false), r, s, true) == l
///
/// The Eth2.0 spec mostly uses shuffling with `forwards == false`, because backwards
/// shuffled lists are slightly easier to specify, and slightly easier to compute.
///
/// The forwards shuffling of a list is equivalent to:
///
/// `[indices[x] for i in 0..n, where compute_shuffled_index(x) = i]`
///
/// Whereas the backwards shuffling of a list is:
///
/// `[indices[compute_shuffled_index(i)] for i in 0..n]`
///
/// Returns `None` under any of the following conditions:
///  - `list_size == 0`
///  - `list_size > 2**24`
///  - `list_size > usize::MAX / 2`
pub fn shuffle_list(
    mut input: Vec<usize>,
    rounds: u8,
    seed: &[u8],
    forwards: bool,
) -> Option<Vec<usize>> {
    let list_size = input.len();

    if input.is_empty() || list_size > usize::MAX / 2 || list_size > 2_usize.pow(24) || rounds == 0
    {
        return None;
    }

    let mut buf = Buf::new(seed);

    let mut r = if forwards { 0 } else { rounds - 1 };

    loop {
        buf.set_round(r);

        let pivot = (buf.raw_pivot() % list_size as u64) as usize;
        let mirror = (pivot + 1) >> 1;

        buf.mix_in_position(pivot >> 8);
        let mut source = buf.hash();
        let mut byte_v = source[(pivot & 0xff) >> 3];

        for i in 0..mirror {
            let j = pivot - i;

            if j & 0xff == 0xff {
                buf.mix_in_position(j >> 8);
                source = buf.hash();
            }

            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            let bit_v = (byte_v >> (j & 0x07)) & 0x01;

            masked_swap(&mut input, i, j, bit_v);
        }

        let mirror = (pivot + list_size + 1) >> 1;
        let end = list_size - 1;

        buf.mix_in_position(end >> 8);
        let mut source = buf.hash();
        let mut byte_v = source[(end & 0xff) >> 3];

        for (loop_iter, i) in ((pivot + 1)..mirror).enumerate() {
            let j = end - loop_iter;

            if j & 0xff == 0xff {
                buf.mix_in_position(j >> 8);
                source = buf.hash();
            }

            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            let bit_v = (byte_v >> (j & 0x07)) & 0x01;

            masked_swap(&mut input, i, j, bit_v);
        }

        if forwards {
            r += 1;
            if r == rounds {
                break;
            }
        } else {
            if r == 0 {
                break;
            }
            r -= 1;
        }
    }

    Some(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SIZES: [usize; 12] = [1, 2, 3, 7, 8, 9, 255, 256, 257, 511, 512, 513];
    const TEST_ROUNDS: [u8; 3] = [1, 17, 90];

    fn test_seeds() -> [[u8; 32]; 3] {
        [[0; 32], [42; 32], std::array::from_fn(|index| index as u8)]
    }

    // Original implementation used for differential testing.
    fn shuffle_list_reference(
        mut input: Vec<usize>,
        rounds: u8,
        seed: &[u8],
        forwards: bool,
    ) -> Option<Vec<usize>> {
        let list_size = input.len();

        if input.is_empty()
            || list_size > usize::MAX / 2
            || list_size > 2_usize.pow(24)
            || rounds == 0
        {
            return None;
        }

        let mut buf = Buf::new(seed);
        let mut round = if forwards { 0 } else { rounds - 1 };

        loop {
            buf.set_round(round);

            let pivot = (buf.raw_pivot() % list_size as u64) as usize;
            let mirror = (pivot + 1) >> 1;

            buf.mix_in_position(pivot >> 8);
            let mut source = buf.hash();
            let mut byte = source[(pivot & 0xff) >> 3];

            for i in 0..mirror {
                let j = pivot - i;

                if j & 0xff == 0xff {
                    buf.mix_in_position(j >> 8);
                    source = buf.hash();
                }

                if j & 0x07 == 0x07 {
                    byte = source[(j & 0xff) >> 3];
                }
                let bit = (byte >> (j & 0x07)) & 0x01;

                if bit == 1 {
                    input.swap(i, j);
                }
            }

            let mirror = (pivot + list_size + 1) >> 1;
            let end = list_size - 1;

            buf.mix_in_position(end >> 8);
            let mut source = buf.hash();
            let mut byte = source[(end & 0xff) >> 3];

            for (loop_iter, i) in ((pivot + 1)..mirror).enumerate() {
                let j = end - loop_iter;

                if j & 0xff == 0xff {
                    buf.mix_in_position(j >> 8);
                    source = buf.hash();
                }

                if j & 0x07 == 0x07 {
                    byte = source[(j & 0xff) >> 3];
                }
                let bit = (byte >> (j & 0x07)) & 0x01;

                if bit == 1 {
                    input.swap(i, j);
                }
            }

            if forwards {
                round += 1;
                if round == rounds {
                    break;
                }
            } else {
                if round == 0 {
                    break;
                }
                round -= 1;
            }
        }

        Some(input)
    }

    #[test]
    fn returns_none_for_zero_length_list() {
        assert_eq!(None, shuffle_list(vec![], 90, &[42, 42], true));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn sanity_check_constants() {
        assert!(TOTAL_SIZE > SEED_SIZE);
        assert!(TOTAL_SIZE > PIVOT_VIEW_SIZE);
        assert!(mem::size_of::<usize>() >= POSITION_WINDOW_SIZE);
    }

    #[test]
    fn matches_conditional_reference() {
        for size in TEST_SIZES {
            let input: Vec<_> = (0..size).map(|value| value.wrapping_mul(17)).collect();

            for rounds in TEST_ROUNDS {
                for seed in test_seeds() {
                    for forwards in [true, false] {
                        assert_eq!(
                            shuffle_list(input.clone(), rounds, &seed, forwards),
                            shuffle_list_reference(input.clone(), rounds, &seed, forwards),
                            "size={size}, rounds={rounds}, seed={seed:?}, forwards={forwards}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn matches_conditional_reference_for_large_list() {
        let input: Vec<_> = (0..65_537).collect();
        let seed = [42; 32];

        for forwards in [true, false] {
            assert_eq!(
                shuffle_list(input.clone(), 90, &seed, forwards),
                shuffle_list_reference(input.clone(), 90, &seed, forwards),
                "forwards={forwards}"
            );
        }
    }

    #[test]
    fn reverse_matches_compute_shuffled_index() {
        for size in [1, 2, 3, 8, 9, 255, 256, 257, 1_024, 1_025] {
            for rounds in [1, 90] {
                for seed in test_seeds() {
                    let expected: Option<Vec<_>> = (0..size)
                        .map(|index| crate::compute_shuffled_index(index, size, &seed, rounds))
                        .collect();

                    assert_eq!(
                        shuffle_list((0..size).collect(), rounds, &seed, false),
                        expected,
                        "size={size}, rounds={rounds}, seed={seed:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn forward_then_reverse_restores_input() {
        let seed = [42; 32];

        for size in [1, 2, 9, 257, 513] {
            let input: Vec<_> = (0..size).map(|value| value % 11).collect();

            for rounds in [1, 90] {
                let restored = shuffle_list(input.clone(), rounds, &seed, true)
                    .and_then(|shuffled| shuffle_list(shuffled, rounds, &seed, false));

                assert_eq!(
                    restored,
                    Some(input.clone()),
                    "size={size}, rounds={rounds}"
                );
            }
        }
    }
}
