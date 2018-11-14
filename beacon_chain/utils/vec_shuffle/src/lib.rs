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

    for i in 0..(list.len().saturating_sub(1)) {
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
    use super::hashing::canonical_hash;
    use super::*;
    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn test_shuffling() {
        let mut file = File::open("./src/specs/shuffle_test_vectors.yaml").unwrap();
        let mut yaml_str = String::new();

        file.read_to_string(&mut yaml_str).unwrap();

        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];
        let test_cases = doc["test_cases"].as_vec();

        for test_case in test_cases.unwrap() {
            let input = test_case["input"].clone().into_vec().unwrap();
            let output = test_case["output"].clone().into_vec().unwrap();
            let seed_bytes = test_case["seed"].as_str().unwrap().as_bytes();
            let mut seed;

            if seed_bytes.len() > 0 {
                seed = canonical_hash(seed_bytes);
            } else {
                seed = vec![];
            }

            let mut s = shuffle(&seed, input).unwrap();

            assert_eq!(s, output);
        }
    }
}
