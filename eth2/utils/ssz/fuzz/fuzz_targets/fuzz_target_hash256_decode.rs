#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ethereum_types::H256;
use ssz::{DecodeError, decode};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<H256, DecodeError> = decode(data);
    if data.len() == 32 {
        // Should have valid result
        let hash = result.unwrap();
        assert_eq!(hash, H256::from_slice(&data[..32]));
    } else {
        // Length of less than 32 should return error
        assert!(result.is_err());
    }
});
