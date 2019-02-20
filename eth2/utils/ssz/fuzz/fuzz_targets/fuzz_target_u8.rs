#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, Decodable, Encodable};

// Fuzz ssz_decode(u8)
fuzz_target!(|data: &[u8]| {
    let result: Result<(u8, usize), DecodeError> = Decodable::ssz_decode(data, 0);
    if data.len() > 0 {
        // Should have valid result
        let (number_u8, index) = result.unwrap();
        assert_eq!(number_u8, data[0]);
        assert_eq!(index, 1);
    } else {
        // Length of 0 should return error
        assert_eq!(result, Err(DecodeError::TooShort));
    }
});
