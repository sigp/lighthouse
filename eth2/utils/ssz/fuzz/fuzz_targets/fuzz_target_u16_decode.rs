#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, decode};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<u16, DecodeError> = decode(data);
    if data.len() == 2 {
        // Valid result
        let number_u16 = result.unwrap();
        let val = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(number_u16, val);
    } else {
        // Length of 0 or 1 should return error
        assert!(result.is_err());
    }
});
