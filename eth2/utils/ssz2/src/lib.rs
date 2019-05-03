/*
 * This is a WIP of implementing an alternative
 * serialization strategy. It attempts to follow Vitalik's
 * "simpleserialize" format here:
 * https://github.com/ethereum/beacon_chain/blob/master/beacon_chain/utils/simpleserialize.py
 *
 * This implementation is not final and would almost certainly
 * have issues.
 */
/*
extern crate bytes;
extern crate ethereum_types;

pub mod decode;
*/
mod decode;
mod encode;

pub use decode::{Decodable, DecodeError};
pub use encode::{Encodable, SszStream};

pub const BYTES_PER_LENGTH_OFFSET: usize = 4;
pub const MAX_LENGTH_VALUE: usize = 1 << (BYTES_PER_LENGTH_OFFSET * 8) - 1;

/// Convenience function to SSZ encode an object supporting ssz::Encode.
pub fn ssz_encode<T>(val: &T) -> Vec<u8>
where
    T: Encodable,
{
    let mut ssz_stream = SszStream::new();
    ssz_stream.append(val);
    ssz_stream.drain()
}

/*

mod impl_decode;
mod impl_encode;

pub use crate::decode::{decode, decode_ssz_list, Decodable, DecodeError};
pub use crate::encode::{Encodable, SszStream};

pub use hashing::hash;

pub const LENGTH_BYTES: usize = 4;
pub const MAX_LIST_SIZE: usize = 1 << (4 * 8);


#[cfg(test)]
mod tests {
    extern crate hex;
    extern crate yaml_rust;

    use self::yaml_rust::yaml;
    use super::*;
    use std::{fs::File, io::prelude::*, path::PathBuf};

    #[test]
    pub fn test_vector_uint_bounds() {
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/test_vectors/uint_bounds.yaml");

            File::open(file_path_buf).unwrap()
        };
        let mut yaml_str = String::new();
        file.read_to_string(&mut yaml_str).unwrap();
        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];

        // Load test cases
        let test_cases = doc["test_cases"].clone();

        for test_case in test_cases {
            // Only the valid cases are checked as parse::<uX>() will fail for all invalid cases
            if test_case["valid"].as_bool().unwrap() {
                // Convert test vector 'ssz' encoded yaml to Vec<u8>
                let ssz = test_case["ssz"].as_str().unwrap().trim_start_matches("0x");
                let test_vector_bytes = hex::decode(ssz).unwrap();

                // Convert test vector 'value' to ssz encoded bytes
                let mut bytes: Vec<u8>;
                match test_case["type"].as_str().unwrap() {
                    "uint8" => {
                        let value: u8 = test_case["value"].as_str().unwrap().parse::<u8>().unwrap();
                        bytes = ssz_encode::<u8>(&value); // check encoding

                        // Check decoding
                        let decoded = decode::<u8>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    "uint16" => {
                        let value: u16 =
                            test_case["value"].as_str().unwrap().parse::<u16>().unwrap();
                        bytes = ssz_encode::<u16>(&value);

                        // Check decoding
                        let decoded = decode::<u16>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    "uint32" => {
                        let value: u32 =
                            test_case["value"].as_str().unwrap().parse::<u32>().unwrap();
                        bytes = ssz_encode::<u32>(&value);

                        // Check decoding
                        let decoded = decode::<u32>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    "uint64" => {
                        let value: u64 =
                            test_case["value"].as_str().unwrap().parse::<u64>().unwrap();
                        bytes = ssz_encode::<u64>(&value);

                        // Check decoding
                        let decoded = decode::<u64>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    _ => continue,
                };
                assert_eq!(test_vector_bytes, bytes);
            }
        }
    }

    #[test]
    pub fn test_vector_uint_random() {
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/test_vectors/uint_random.yaml");

            File::open(file_path_buf).unwrap()
        };
        let mut yaml_str = String::new();
        file.read_to_string(&mut yaml_str).unwrap();
        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];

        // Load test cases
        let test_cases = doc["test_cases"].clone();

        for test_case in test_cases {
            // Only the valid cases are checked as parse::<uX>() will fail for all invalid cases
            if test_case["valid"].as_bool().unwrap() {
                // Convert test vector 'ssz' encoded yaml to Vec<u8>
                let ssz = test_case["ssz"].as_str().unwrap().trim_start_matches("0x");
                let test_vector_bytes = hex::decode(ssz).unwrap();

                // Convert test vector 'value' to ssz encoded bytes
                let mut bytes: Vec<u8>;
                match test_case["type"].as_str().unwrap() {
                    "uint8" => {
                        let value: u8 = test_case["value"].as_str().unwrap().parse::<u8>().unwrap();
                        bytes = ssz_encode::<u8>(&value); // check encoding

                        // Check decoding
                        let decoded = decode::<u8>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    "uint16" => {
                        let value: u16 =
                            test_case["value"].as_str().unwrap().parse::<u16>().unwrap();
                        bytes = ssz_encode::<u16>(&value);

                        // Check decoding
                        let decoded = decode::<u16>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    "uint32" => {
                        let value: u32 =
                            test_case["value"].as_str().unwrap().parse::<u32>().unwrap();
                        bytes = ssz_encode::<u32>(&value);

                        // Check decoding
                        let decoded = decode::<u32>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    "uint64" => {
                        let value: u64 =
                            test_case["value"].as_str().unwrap().parse::<u64>().unwrap();
                        bytes = ssz_encode::<u64>(&value);

                        // Check decoding
                        let decoded = decode::<u64>(&test_vector_bytes).unwrap();
                        assert_eq!(decoded, value);
                    }
                    _ => continue,
                };
                assert_eq!(test_vector_bytes, bytes);
            }
        }
    }

    #[test]
    pub fn test_vector_uint_wrong_length() {
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/test_vectors/uint_wrong_length.yaml");

            File::open(file_path_buf).unwrap()
        };
        let mut yaml_str = String::new();
        file.read_to_string(&mut yaml_str).unwrap();
        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];

        // Load test cases
        let test_cases = doc["test_cases"].clone();

        for test_case in test_cases {
            // Convert test vector 'ssz' encoded yaml to Vec<u8>
            let ssz = test_case["ssz"].as_str().unwrap().trim_start_matches("0x");
            let test_vector_bytes = hex::decode(ssz).unwrap();

            // Attempt to decode invalid ssz bytes
            match test_case["type"].as_str().unwrap() {
                "uint8" => {
                    let decoded = decode::<u8>(&test_vector_bytes);
                    assert!(decoded.is_err());
                }
                "uint16" => {
                    let decoded = decode::<u16>(&test_vector_bytes);
                    assert!(decoded.is_err());
                }
                "uint32" => {
                    let decoded = decode::<u32>(&test_vector_bytes);
                    assert!(decoded.is_err());
                }
                "uint64" => {
                    let decoded = decode::<u64>(&test_vector_bytes);
                    assert!(decoded.is_err());
                }
                _ => continue,
            };
        }
    }
}
*/
