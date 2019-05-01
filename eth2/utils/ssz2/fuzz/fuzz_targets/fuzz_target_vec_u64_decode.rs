#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{decode, DecodeError};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let _result: Result<Vec<u64>, DecodeError> = decode(data);
});
