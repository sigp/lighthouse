#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, decode};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<u8, DecodeError> = decode(data);
    if data.len() == 1 {
        // Should have valid result
        let number_u8 = result.unwrap();
        assert_eq!(number_u8, data[0]);
    } else {
        // Length not 1 should return error
        assert!(result.is_err());
    }
});
