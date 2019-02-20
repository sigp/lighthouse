#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<(u8, usize), DecodeError> = Decodable::ssz_decode(data, 0);
    if data.len() >= 1 {
        // Should have valid result
        let (number_u8, index) = result.unwrap();
        // TODO: change to little endian bytes
        // https://github.com/sigp/lighthouse/issues/215
        assert_eq!(index, 1);
        assert_eq!(number_u8, data[0]);
    } else {
        // Length of 0 should return error
        assert_eq!(result, Err(DecodeError::TooShort));
    }
});
