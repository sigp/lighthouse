#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ethereum_types::H256;
use ssz::{DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<(H256, usize), DecodeError> = Decodable::ssz_decode(data, 0);
    if data.len() >= 32 {
        // Should have valid result
        let (hash, index) = result.unwrap();
        assert_eq!(index, 32);
        assert_eq!(hash, H256::from_slice(&data[..32]));
    } else {
        // Length of less than 32 should return error
        assert_eq!(result, Err(DecodeError::TooShort));
    }
});
