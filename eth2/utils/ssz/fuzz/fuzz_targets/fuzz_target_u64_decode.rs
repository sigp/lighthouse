#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<(u64, usize), DecodeError> = Decodable::ssz_decode(data, 0);
    if data.len() >= 8 {
        // Valid result
        let (number_u64, index) = result.unwrap();
        assert_eq!(index, 8);
        // TODO: change to little endian bytes
        // https://github.com/sigp/lighthouse/issues/215
        let val = u64::from_be_bytes([
            data[0],
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
            ]);
        assert_eq!(number_u64, val);
    } else {
        // Length less then 8 should return error
        assert_eq!(result, Err(DecodeError::TooShort));
    }
});
