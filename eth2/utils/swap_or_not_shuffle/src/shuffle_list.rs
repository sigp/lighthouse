use bytes::Buf;
use hashing::hash;
use int_to_bytes::int_to_bytes4;
use std::io::Cursor;

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

fn bytes_to_int64(bytes: &[u8]) -> u64 {
    let mut cursor = Cursor::new(bytes);
    cursor.get_u64_le()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::{fs::File, io::prelude::*, path::PathBuf};
    use yaml_rust::yaml;

    #[test]
    fn returns_none_for_zero_length_list() {
        assert_eq!(None, shuffle_list(vec![], 90, &[42, 42], true));
    }

    #[test]
    fn test_vectors() {
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/specs/test_vector_permutated_index.yml");

            File::open(file_path_buf).unwrap()
        };

        let mut yaml_str = String::new();

        file.read_to_string(&mut yaml_str).unwrap();

        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];
        let test_cases = doc["test_cases"].as_vec().unwrap();

        for (i, test_case) in test_cases.iter().enumerate() {
            let index = test_case["index"].as_i64().unwrap() as usize;
            let list_size = test_case["list_size"].as_i64().unwrap() as usize;
            let permutated_index = test_case["permutated_index"].as_i64().unwrap() as usize;
            let shuffle_round_count = test_case["shuffle_round_count"].as_i64().unwrap();
            let seed_string = test_case["seed"].clone().into_string().unwrap();
            let seed = hex::decode(seed_string.replace("0x", "")).unwrap();

            let shuffle_round_count = if shuffle_round_count < (u8::max_value() as i64) {
                shuffle_round_count as u8
            } else {
                panic!("shuffle_round_count must be a u8")
            };

            let list: Vec<usize> = (0..list_size).collect();

            let shuffled =
                shuffle_list(list.clone(), shuffle_round_count, &seed[..], true).unwrap();

            assert_eq!(
                list[index], shuffled[permutated_index],
                "Failure on case #{} index: {}, list_size: {}, round_count: {}, seed: {}",
                i, index, list_size, shuffle_round_count, seed_string
            );
        }
    }
}
