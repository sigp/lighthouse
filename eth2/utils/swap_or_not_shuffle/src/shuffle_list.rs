use eth2_hashing::hash;
use int_to_bytes::int_to_bytes4;

const SEED_SIZE: usize = 32;
const ROUND_SIZE: usize = 1;
const POSITION_WINDOW_SIZE: usize = 4;
const PIVOT_VIEW_SIZE: usize = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE: usize = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

/// Shuffles an entire list in-place.
///
/// Note: this is equivalent to the `get_permutated_index` function, except it shuffles an entire
/// list not just a single index. With large lists this function has been observed to be 250x
/// faster than running `get_permutated_index` across an entire list.
///
/// Credits to [@protolambda](https://github.com/protolambda) for defining this algorithm.
///
/// Shuffles if `forwards == true`, otherwise un-shuffles.
/// It holds that: shuffle_list(shuffle_list(l, r, s, true), r, s, false) == l
///           and: shuffle_list(shuffle_list(l, r, s, false), r, s, true) == l
///
/// Returns `None` under any of the following conditions:
///  - `list_size == 0`
///  - `list_size > 2**24`
///  - `list_size > usize::max_value() / 2`
pub fn shuffle_list(
    mut input: Vec<usize>,
    rounds: u8,
    seed: &[u8],
    forwards: bool,
) -> Option<Vec<usize>> {
    let list_size = input.len();

    if input.is_empty()
        || list_size > usize::max_value() / 2
        || list_size > 2_usize.pow(24)
        || rounds == 0
    {
        return None;
    }

    let mut buf: Vec<u8> = Vec::with_capacity(TOTAL_SIZE);

    let mut r = if forwards { 0 } else { rounds - 1 };

    buf.extend_from_slice(seed);

    loop {
        buf.splice(SEED_SIZE.., vec![r]);

        let pivot = bytes_to_int64(&hash(&buf[0..PIVOT_VIEW_SIZE])[0..8]) as usize % list_size;

        let mirror = (pivot + 1) >> 1;

        buf.splice(PIVOT_VIEW_SIZE.., int_to_bytes4((pivot >> 8) as u32));
        let mut source = hash(&buf[..]);
        let mut byte_v = source[(pivot & 0xff) >> 3];

        for i in 0..mirror {
            let j = pivot - i;

            if j & 0xff == 0xff {
                buf.splice(PIVOT_VIEW_SIZE.., int_to_bytes4((j >> 8) as u32));
                source = hash(&buf[..]);
            }

            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            let bit_v = (byte_v >> (j & 0x07)) & 0x01;

            if bit_v == 1 {
                input.swap(i, j);
            }
        }

        let mirror = (pivot + list_size + 1) >> 1;
        let end = list_size - 1;

        buf.splice(PIVOT_VIEW_SIZE.., int_to_bytes4((end >> 8) as u32));
        let mut source = hash(&buf[..]);
        let mut byte_v = source[(end & 0xff) >> 3];

        for (loop_iter, i) in ((pivot + 1)..mirror).enumerate() {
            let j = end - loop_iter;

            if j & 0xff == 0xff {
                buf.splice(PIVOT_VIEW_SIZE.., int_to_bytes4((j >> 8) as u32));
                source = hash(&buf[..]);
            }

            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            let bit_v = (byte_v >> (j & 0x07)) & 0x01;

            if bit_v == 1 {
                input.swap(i, j);
            }
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

fn bytes_to_int64(slice: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&slice[0..8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_zero_length_list() {
        assert_eq!(None, shuffle_list(vec![], 90, &[42, 42], true));
    }
}
