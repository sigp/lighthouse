use bytes::{Buf, BufMut, BytesMut};
use hashing::hash;
use std::cmp::max;
use std::io::Cursor;

pub fn get_permutated_index(
    index: usize,
    list_size: usize,
    seed: &[u8],
    shuffle_round_count: usize,
) -> usize {
    let mut index = index;
    for round in 0..shuffle_round_count {
        let pivot = bytes_to_int64(&hash_with_round(seed, round)[..]) as usize % list_size;
        let flip = (pivot - index) % list_size;
        let position = max(index, flip);
        let source = hash_with_round_and_position(seed, round, position);
        let byte = source[(position % 256) / 8];
        let bit = (byte >> (position % 8)) % 2;
        index = if bit == 1 { flip } else { index }
    }
    index
}

fn hash_with_round_and_position(seed: &[u8], round: usize, position: usize) -> Vec<u8> {
    let mut seed = seed.to_vec();
    seed.append(&mut int_to_bytes1(round as u64));
    seed.append(&mut int_to_bytes4(position as u64 / 256));
    hash(&seed[..])
}

fn hash_with_round(seed: &[u8], round: usize) -> Vec<u8> {
    let mut seed = seed.to_vec();
    seed.append(&mut int_to_bytes1(round as u64));
    hash(&seed[..])
}

fn int_to_bytes1(int: u64) -> Vec<u8> {
    let mut bytes = BytesMut::with_capacity(8);
    bytes.put_u64_le(int);
    vec![bytes[0]]
}

fn int_to_bytes4(int: u64) -> Vec<u8> {
    let mut bytes = BytesMut::with_capacity(8);
    bytes.put_u64_le(int);
    bytes[0..4].to_vec()
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
    fn test_shuffling() {
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/specs/permutated_index_test_vectors.yaml");

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
            let shuffle_round_count = test_case["shuffle_round_count"].as_i64().unwrap() as usize;
            let seed_string = test_case["seed"].clone().into_string().unwrap();
            let seed = hex::decode(seed_string.replace("0x", "")).unwrap();

            println!("case: {}", i);

            assert_eq!(
                permutated_index,
                get_permutated_index(index, list_size, &seed[..], shuffle_round_count),
                "Failure on case #{} index: {}, list_size: {}, round_count: {}, seed: {}",
                i,
                index,
                list_size,
                shuffle_round_count,
                seed_string,
            );

            /*
            let input = test_case["input"].clone().into_vec().unwrap();
            let output = test_case["output"].clone().into_vec().unwrap();
            let seed_bytes = test_case["seed"].as_str().unwrap().as_bytes();

            let seed = if seed_bytes.len() > 0 {
                hash(seed_bytes)
            } else {
                vec![]
            };

            assert_eq!(shuffle(&seed, input).unwrap(), output);
            */
        }
    }
}
