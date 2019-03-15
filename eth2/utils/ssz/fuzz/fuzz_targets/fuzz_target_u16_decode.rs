#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<(u16, usize), DecodeError> = Decodable::ssz_decode(data, 0);
    if data.len() >= 2 {
        // Valid result
        let (number_u16, index) = result.unwrap();
        assert_eq!(index, 2);
        // TODO: change to little endian bytes
        // https://github.com/sigp/lighthouse/issues/215
        let val = u16::from_be_bytes([data[0], data[1]]);
        assert_eq!(number_u16, val);
    } else {
        // Length of 0 or 1 should return error
        assert_eq!(result, Err(DecodeError::TooShort));
    }
});
