/// A library for performing deterministic, pseudo-random shuffling on a vector.
///
/// This library is designed to confirm to the Ethereum 2.0 specification.
extern crate hashing;

mod rng;

use self::rng::ShuffleRng;

#[derive(Debug)]
pub enum ShuffleErr {
    ExceedsListLength,
}

/// Performs a deterministic, in-place shuffle of a vector.
///
/// The final order of the shuffle is determined by successive hashes
/// of the supplied `seed`.
///
/// This is a Fisher-Yates-Durtstenfeld shuffle.
pub fn shuffle<T>(seed: &[u8], mut list: Vec<T>) -> Result<Vec<T>, ShuffleErr> {
    let mut rng = ShuffleRng::new(seed);

    if list.len() > rng.rand_max as usize {
        return Err(ShuffleErr::ExceedsListLength);
    }

    if list.is_empty() {
        return Ok(list);
    }

    for i in 0..(list.len() - 1) {
        let n = list.len() - i;
        let j = rng.rand_range(n as u32) as usize + i;
        list.swap(i, j);
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    extern crate yaml_rust;

    use self::yaml_rust::yaml;

    use std::{fs::File, io::prelude::*, path::PathBuf};

    use super::{hashing::canonical_hash, *};

    #[test]
    fn test_shuffling() {
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/specs/shuffle_test_vectors.yaml");

            File::open(file_path_buf).unwrap()
        };

        let mut yaml_str = String::new();

        file.read_to_string(&mut yaml_str).unwrap();

        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];
        let test_cases = doc["test_cases"].as_vec().unwrap();

        for test_case in test_cases {
            let input = test_case["input"].clone().into_vec().unwrap();
            let output = test_case["output"].clone().into_vec().unwrap();
            let seed_bytes = test_case["seed"].as_str().unwrap().as_bytes();

            let seed = if seed_bytes.len() > 0 {
                canonical_hash(seed_bytes)
            } else {
                vec![]
            };

            assert_eq!(shuffle(&seed, input).unwrap(), output);
        }
    }
}
