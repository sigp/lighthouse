#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, decode};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<u32, DecodeError> = decode(data);
    if data.len() == 4 {
        // Valid result
        let number_u32 = result.unwrap();
        let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(number_u32, val);
    } else {
        // Length not 4 should return error
        assert!(result.is_err());
    }
});
