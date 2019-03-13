#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<(bool, usize), DecodeError> = Decodable::ssz_decode(data, 0);
    if data.len() >= 1 {
        // TODO: change to little endian bytes
        // https://github.com/sigp/lighthouse/issues/215
        if data[0] == u8::pow(2,7) {
            let (val_bool, index) = result.unwrap();
            assert!(val_bool);
            assert_eq!(index, 1);
        } else if data[0] == 0 {
            let (val_bool, index) = result.unwrap();
            assert!(!val_bool);
            assert_eq!(index, 1);
        } else {
            assert_eq!(result, Err(DecodeError::Invalid));
        }
    } else {
        // Length of 0 should return error
        assert_eq!(result, Err(DecodeError::TooShort));
    }
});
